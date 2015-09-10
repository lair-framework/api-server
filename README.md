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
