# verdaccio-regman

Verdaccio authentication plugin for [Registry Manager](https://github.com/andris9/registry-manager).

### Installation

```
npm install verdaccio-regman
```

### Configuration

```
auth:
  regman:
    db_file: /path/to/registry-manager-users.json # must be readable
```

### Usage

_regman_ plugin uses Registry Manager user database for authentication. Adding users from command line is not allowed.

Package access uses Verdaccio configuration.

Publishing is only allowed to users with `admin` or `publish` tags. Verdaccion configuration is ignored.

## License

**ISC**
