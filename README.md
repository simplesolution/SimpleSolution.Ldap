# SimpleSolution.Ldap
Neos Plugin which allows you to login into the Neos Backend with an Ldap server

It doesn't get simpler than this to login via ldap.

At the moment this plugin is only tested with OpenLDAP, but it should work on every ldap server, if not, consider making a pull request.

## Requirements

 * php >= 7
 
 ## How to Use
 
 Just configurate your ldap server in your Settings.yml and thats it, heres the default configuration:
 
 ```yml
SimpleSolution:
  Ldap:
    host:
      hosts: ['127.0.0.1']
      base_dn: ou=your,dc=ldap,dc=at
      username: ~
      password: ~
      port: 389
    fields:
      usernameAttribute: 'uid' 
    roles: 
      neos-admin: 'Neos.Neos:Administrator'
      neos-editor: 'Neos.Neos:Editor'
    defaultRole: ~
    additionalHosts: ~
```

The configuration under **host** has the same parameters as the configuration from [Adldap2](https://github.com/Adldap2/Adldap2/blob/master/docs/setup.md#configuration).
The **usernameAttribute** set the field which you wanna map to your username in neos. **roles** defines the mapping on which group should display which Neos Role and the **defaultRole** acts like a fallback when either no mappings are defined or the user has no groups in ldap.
With the **additionalHosts** setting you cann define additional ldap servers, but be careful the more server the slower will be the authentication process. To add an additionalHost just add this:

 ```yml
SimpleSolution:
  Ldap:
    host:
      hosts: ['127.0.0.1']
      base_dn: ou=your,dc=ldap,dc=at
      username: ~
      password: ~
      port: 389
    fields:
      usernameAttribute: 'uid' 
    roles: 
      neos-admin: 'Neos.Neos:Administrator'
      neos-editor: 'Neos.Neos:Editor'
    defaultRole: ~
    additionalHosts:
      anotherHost:
        host:
          hosts: ['127.0.0.1']  
          base_dn: ou=your,dc=ldap,dc=at
          username: ~
          password: ~
          port: 389
        fields:
          usernameAttribute: 'uid' 
        roles: 
          neos-admin: 'Neos.Neos:Administrator'
          neos-editor: 'Neos.Neos:Editor'
        defaultRole: ~
```

The additional Host has the same configuration options than the default one.

## Authors

[Tobias Franek (tobias.franek@gmail.com)](https://github.com/TobiasFranek)
