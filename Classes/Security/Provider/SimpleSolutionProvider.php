<?php

declare(strict_types=1);

namespace SimpleSolution\Ldap\Security\Provider;

use Neos\Flow\Annotations as Flow;
use SimpleSolution\Ldap\Exceptions\LdapUserNotFoundException;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\Authentication\Token\UsernamePassword;
use Neos\Flow\Security\Authentication\Token\UsernamePasswordHttpBasic;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Flow\Security\Policy\Role;
use Neos\Party\Domain\Service\PartyService;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Neos\Party\Domain\Repository\PartyRepository;
use Neos\Neos\Domain\Model\User;
use Neos\ContentRepository\Domain\Model\Workspace;
use Neos\ContentRepository\Domain\Repository\WorkspaceRepository;
use Neos\Neos\Utility\User as UserUtility;
use Neos\Party\Domain\Model\PersonName;
use Adldap\Adldap;
use Adldap\Models\User as LdapUser;
use Adldap\Connections\Provider;
use Adldap\Connections\ProviderInterface;
use Adldap\Auth\BindException;

/**
 * An authentication provider that authenticates
 * Neos\Flow\Security\Authentication\Token\UsernamePassword tokens.
 * The accounts are stored in the Content Repository.
 * 
 * @author Tobias Franek <tobias.franek@simplesolution.at>
 * @license MIT - Simple Solution <office@simplesolution.at> 
 */
class SimpleSolutionProvider extends AbstractProvider
{

    /**
     * @Flow\Inject
     * @var PartyRepository
     */
    protected $partyRepository;
    /**
     * @Flow\Inject
     * @var PartyService
     */
    protected $partyService;
    /**
     * @Flow\Inject(lazy=false)
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @var AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @var HashService
     * @Flow\Inject
     */
    protected $hashService;

    /**
     * @var Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var \Neos\Flow\Persistence\PersistenceManagerInterface
     * @Flow\Inject
     */
    protected $persistenceManager;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var AccountFactory
     */
    protected $accountFactory;

    /**
     * @Flow\Inject
     * @var \Neos\Neos\Domain\Service\UserService
     */
    protected $userDomainService;

    /**
     * @Flow\Inject
     * @var WorkspaceRepository
     */
    protected $workspaceRepository;

    /**
     * @Flow\InjectConfiguration("userInterface.defaultLanguage")
     * @var string
     */
    protected $defaultLanguageIdentifier;

    /**
     * @var array
     */
    protected $settings;

    /**
     * Inject the settings
     *
     * @param array $settings
     * @return void
     */
    public function injectSettings(array $settings) 
    {
        $additionalHosts = $settings['additionalHosts'];
        unset($settings['additionalHosts']);
        // set the default settings
        $this->settings['default'] = $settings;
        // set all additionalHosts
        if(!empty($additionalHosts)) {
            foreach($additionalHosts as $additionalHostName => $additionalHostConfig) {
                $this->settings[$additionalHostName] = $additionalHostConfig;
            }
        }
    }

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return [UsernamePassword::class, UsernamePasswordHttpBasic::class];
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        $credentials = $authenticationToken->getCredentials();
        $providerName = 'Neos.Neos:Backend';
        // searches for a normal account
        $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $providerName);
        // if no such account was found try with the @ldap suffix
        if(!$account) {
            $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'] . '@ldap', $providerName);
        }
        // checks if the account exists
        if(!$account) {
            // if no account exists but there is an ldap user
            // create a new neos user mapped to this user
            
            // connect to ldap
            try {
                $providers = $this->connectToLdap($authenticationToken);
            } catch(BindException $e) {
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                return;
            }

            // get the user from ldap
            try {
                $userResult = $this->getLdapUser($credentials['username'], $authenticationToken, $providers);
            } catch(LdapUserNotFoundException $e) {
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                return;
            }

            $user = $userResult['user'];

            // set the provider to the one used for the fetched user
            $provider = $providers[$userResult['providerName']];

            // get the DistinguishedName that will be used to authenticate the user
            $userDn = $user->getDistinguishedName();

            // login the user
            if($provider->auth()->attempt($userDn, $credentials['password'])) {
                $roles = $this->getRoles($user, $provider, $userResult['providerName']);

                // create neos user and log him into neos
                $account = $this->accountFactory->createAccountWithPassword($credentials['username'] . '@ldap', $credentials['password'], $roles, $authenticationProviderName = 'Neos.Neos:Backend', $passwordHashingStrategy = 'default');
                $user = $this->createUser($credentials['username'], $credentials['password'], $user->getFirstName(), $user->getLastName(), $roles, 'Neos.Neos:Backend', $account);
                $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                $authenticationToken->setAccount($account);
                $this->accountRepository->add($account);
                $this->entityManager->persist($user);
                $this->persistenceManager->whitelistObject($account);
                $this->entityManager->flush();
            } else {
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            }
        } else {
            // if account exists check if the account could be an ldap user
            // via the @ldap suffix
            $possibleLdap = explode('@', $account->getAccountIdentifier());
            if(isset($possibleLdap[1]) && $possibleLdap[1] == 'ldap') {
                // connect to ldap
                try {
                    $providers = $this->connectToLdap($authenticationToken);
                } catch(BindException $e) {
                    $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                    return;
                }

                // get user/provider
                try {
                    $userResult = $this->getLdapUser($credentials['username'], $authenticationToken, $providers);
                } catch(LdapUserNotFoundException $e) {
                    $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                    return;
                }

                $neosUser = null;
                $user = $userResult['user'];
                $provider = $providers[$userResult['providerName']];
                $userDn = $user->getDistinguishedName();
                // login user into ldap
                if($provider->auth()->attempt($userDn, $credentials['password'])) {

                    // update the user info with the user info gotten from ldap
                    // and login into neos
                    $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                    $roles = $this->getRoles($user, $provider, $userResult['providerName']);
                    foreach($roles as $key => $role) {
                        $roles[$key] = new Role($role);
                    }
                    $account->setRoles($roles);
                    $neosUser = $this->partyRepository->findOneHavingAccount($account);
                    $personName = $neosUser->getName();
                    $personName->setFirstName($user->getFirstName());
                    $personName->setLastName($user->getLastName());
                    $neosUser->setName($personName);
                    $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                    $authenticationToken->setAccount($account);
                    $this->persistenceManager->whitelistObject($account);
                } else {
                    $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                    $account->authenticationAttempted(TokenInterface::WRONG_CREDENTIALS);
                }
            } else {
                // if the account is no ldap user execute the standard auth method used by neos
                if(!$this->standardAuthMethod($authenticationToken)) {
                    return;
                }
            }
            // update entities
            if($neosUser) {
                $this->partyRepository->update($neosUser);
            }
            $this->accountRepository->update($account);
            $this->persistenceManager->whitelistObject($account);
        }
    }

    /**
     * this method connect to all configurated hosts and returns the providers in an array
     * @param TokenInterface $authenticationToken pass the Token by Reference
     * @return array
     */
    private function connectToLdap(TokenInterface &$authenticationToken) : array
    {
        $providers = [];
        foreach($this->settings as $name => $config) {
            $ldap = new Adldap();
            $ldap->addProvider($config['host']);
            //connects to the AD
            $providers[$name] = $ldap->connect();
        }
        return $providers;
    }

    /**
     * this function return an array with neos roles that should be set according to the config and ldap groups
     * @param LdapUser $user  
     * @param ProviderInterface $provider
     * @param string $configName
     * @return array
     */
    private function getRoles(LdapUser $user, ProviderInterface $provider, string $configName) : array
    {
        // does things differenty when schema is OpenLDAP
        if(get_class($user->getSchema()) == 'Adldap\Schemas\OpenLDAP') {
            $groups = $provider->search()->groups()->get();
            $hasGroups = [];
            foreach($groups as $group) {
                foreach($group->getMembers() as $member) {
                    if($member->getDistinguishedName() == $user->getDistinguishedName()) {
                            $hasGroups[] = $group->getCommonName();
                    }
                }
            }
        } else {
            $hasGroups = $user->getGroupNames();
        }
        $neosRoles = [];
        // if the user has groups set the neos roles according to the mapping in the configuration
        if($hasGroups) {
            foreach($hasGroups as $group) {
                if(isset($this->settings[$configName]['roles'][$group])) {
                    $neosRoles[] = $this->settings[$configName]['roles'][$group];
                }
            }
        } else {
            // if the user does not have groups but an defaultRole as fallback is defined in the config
            if (isset($this->settings[$configName]['defaultRole'])) {
                $neosRoles[] = $this->settings[$configName]['defaultRole'];
            }
        }
        
        return $neosRoles;
    }

    /**
     * fetches the user and return the user + the providerName where the user was found in
     * @param string $username
     * @param TokenInterface $authenticationToken passed by Reference
     * @param array $providers 
     * @return array
     * @throws LdapUserNotFoundException
     */
    private function getLdapUser(string $username, TokenInterface &$authenticationToken, array $providers) : array
    {
        // loops through all the providers and searchees for the given user
        foreach($providers as $providerName => $provider) {
            if($provider) {
                $search = $provider->search();
            } else {
                return false;
            }
            $user = $search->where($this->settings[$providerName]['fields']['usernameAttribute'], '=', $username)->first();
            if($user) {
                // return user and providerName the user was found in
                return [
                    'user' => $user,
                    'providerName' => $providerName
                ];
            }
        }
        throw new LdapUserNotFoundException();
    }

    /**
     * this is the standard auth method that was in the original Provider
     * @param TokenInterface $authenticationToken
     * @return bool|void
     */
    private function standardAuthMethod(TokenInterface $authenticationToken) 
    {
        if (!($authenticationToken instanceof UsernamePassword)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
        }

        /** @var $account Account */
        $account = null;
        $credentials = $authenticationToken->getCredentials();

        if ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
        }

        if (!is_array($credentials) || !isset($credentials['username']) || !isset($credentials['password'])) {
            return false;
        }

        $providerName = $this->name;
        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function () use ($credentials, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $providerName);
        });

        $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);

        if ($account === null) {
            $this->hashService->validatePassword($credentials['password'], 'bcrypt=>$2a$14$DummySaltToPreventTim,.ingAttacksOnThisProvider');
            return false;
        }

        if ($this->hashService->validatePassword($credentials['password'], $account->getCredentialsSource())) {
            $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
        } else {
            $account->authenticationAttempted(TokenInterface::WRONG_CREDENTIALS);
        }
        $this->accountRepository->update($account);
        $this->persistenceManager->whitelistObject($account);
    }

    /**
     * this method creates an user in neos it is mostly copied from 
     * Neos\Neos\Domain\Service\UserService
     * @param string $username 
     * @param string $password 
     * @param string $firstName 
     * @param string $lastName 
     * @param array $roleIdentifier 
     * @param string $authenticationProviderName 
     * @param Account $account 
     * @return User
     */
    private function createUser(string $username, string $password, string $firstName, string $lastName, array $roleIdentifiers = null, string  $authenticationProviderName = null, Account $account) : User
    {
        $user = new User();
        $name = new PersonName('', $firstName, '', $lastName, '', $username);
        $user->setName($name);

        if ($roleIdentifiers === null) {
            $roleIdentifiers = array('Neos.Neos:Editor');
        }
        $roleIdentifiers = $this->normalizeRoleIdentifiers($roleIdentifiers);
        if (!$user->getAccounts()->contains($account)) {
            $user->addAccount($account);
        }

        $this->createPersonalWorkspace($user, $account);
        return $user;
    }
    
    /**
     * Replaces role identifiers not containing a "." into fully qualified role identifiers from the Neos.Neos namespace.
     * this method is mostly copied from 
     * Neos\Neos\Domain\Service\UserService
     * @param array $roleIdentifiers
     * @return array
     */
    private function normalizeRoleIdentifiers(array $roleIdentifiers) : array
    {
        foreach ($roleIdentifiers as &$roleIdentifier) {
            $roleIdentifier = $this->normalizeRoleIdentifier($roleIdentifier);
        }

        return $roleIdentifiers;
    }
    /**
     * Replaces a role identifier not containing a "." into fully qualified role identifier from the Neos.Neos namespace.
     *
     * this method is mostly copied from 
     * Neos\Neos\Domain\Service\UserService
     * @param string $roleIdentifier
     * @return string
     * @throws NoSuchRoleException
     */
    protected function normalizeRoleIdentifier(string $roleIdentifier) : string
    {
        if (strpos($roleIdentifier, ':') === false) {
            $roleIdentifier = 'Neos.Neos:' . $roleIdentifier;
        }
        if (!$this->policyService->hasRole($roleIdentifier)) {
            throw new NoSuchRoleException(sprintf('The role %s does not exist.', $roleIdentifier), 1422540184);
        }

        return $roleIdentifier;
    }
    /**
     * Creates a personal workspace for the given user's account if it does not exist already.
     * 
     * this method is mostly copied from 
     * Neos\Neos\Domain\Service\UserService
     * 
     * @param User $user The new user to create a workspace for
     * @param Account $account The user's backend account
     * @throws IllegalObjectTypeException
     */
    protected function createPersonalWorkspace(User $user, Account $account)
    {
        $userWorkspaceName = UserUtility::getPersonalWorkspaceNameForUsername($account->getAccountIdentifier());
        $userWorkspace = $this->workspaceRepository->findByIdentifier($userWorkspaceName);
        if ($userWorkspace === null) {

            $liveWorkspace = $this->workspaceRepository->findByIdentifier('live');
            if (!($liveWorkspace instanceof Workspace)) {
                $liveWorkspace = new Workspace('live');
                $liveWorkspace->setTitle('Live');
                $this->workspaceRepository->add($liveWorkspace);
            }

            $userWorkspace = new Workspace($userWorkspaceName, $liveWorkspace, $user);
            $userWorkspace->setTitle((string)$user->getName());
            $this->workspaceRepository->add($userWorkspace);
        }
    }
}
