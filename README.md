# api-server
This is a JSON API for lair. It is used by drones to create, update, and delete data.

## Install
Download a compiles binary for supported operating systems from [here](https://github.com/lair-framework/api-server/releases/latest).

```
$ mv api-server* api-server
$ export MONGO_URL=mongodb://localhost:27017/lair
$ export API_LISTENER=ip:port
$ ./api-server
```

## Transforms
Transforms allow you to use Go plugins to modify a project that is sent as part of an update. Go plugins are Linux only and have been available since v1.8.

### Confguration
The api-server will load all plugins from a directory that is set via the `TRANSFORM_DIR` environment variable. Example:
```
$ export TRANSFORM_DIR=plugins
$ ls plugins
iis.so foo.so bar.so
$ ./api-server
2017/03/03 12:56:05 Loading transform iis.so
2017/03/03 12:56:05 Loading transform foo.so
2017/03/03 12:56:05 Loading transform bar.so
````

### Writing Transforms
Writing transform involves implmenting a single function, `Update(p *lair.Project`. Here is a stub.
```
package main

import (
    lair "github.com/lair-framework/go-lair"
)

func Update(p *lair.Project) {
    for i := range p.Hosts {
        p[i].Host.OS = "Trash"
    }
}
```

This can now be built by running `go build -buildmode=plugin`.
