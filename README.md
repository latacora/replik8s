# Replik8s

Replik8s is a modern open-source Kubernetes auditing and investigation tool. It is designed to address the common limitations of traditional security tools, which rely on narrow data collection and predefined logic. RepliK8s allows cloning Kubernetes clusters and serving back exact replicas of the original data, as well as conducting analysis through a tool-agnostic query language.

This versatility makes it particularly valuable for purple teams, enabling both exploratory investigation and precise identification of misconfigurations and vulnerabilities.

## How it works

Clusters describe their APIs via two sets of endpoints:

* `/openapi/v2` which provides a Swagger 2.0 OpenAPI
* `/api` & `/apis` which details the k8s resources available in the cluster in a RESTy manner

The cluster API is quite simple (endpoints are self-contained and multiple requests aren't required to fetch resources),
which allows using the `/api` and `/apis` endpoints to fetch all the resources. Once we have this data, we can serve
it back to simulate a cluster "offline".

## Usage

Running the standalone JAR:

```shell
java -jar replik8s.jar

Usage: replik8s <command> [options]

Commands:
  collect    Generate a snapshot.
  report     Generate findings.
  serve      Start the server.
  visualize  Visualize snapshot.

Run 'replik8s <command> --help' for more information on a command.
```

### Generating Snapshots

Generating a snapshot:

```shell
java -jar replik8s.jar collect
```

This command supports the following options:
- `--snapshot-dir`: Directory of the snapshots to load. Defaults to `snapshots`.
- `--kubeconfig`: Optional path to the kubeconfig file.

### Serving Snapshots

Serving the snapshots:

```shell
java -jar replik8s.jar serve
```

This command starts a server that serves all snapshots from the `snapshots/` directory. You can specify a different directory with the `--snapshot-dir` flag.

When you run `serve`, a `kubeconfig-all-snapshots.json` file is generated in your project directory. This file is configured with a separate context for each snapshot, allowing you to switch between different points in time.

**Interacting with Snapshots**

You can use this `kubeconfig` file with `kubectl` to interact with the mirrored API.

To list all available snapshot contexts:
```shell
kubectl --kubeconfig kubeconfig-all-snapshots.json config get-contexts
```

To switch to a specific snapshot context:
```shell
kubectl --kubeconfig kubeconfig-all-snapshots.json config use-context <context-name>
```

Once you have selected a context, all subsequent `kubectl` commands will be directed at that specific snapshot:
```shell
kubectl --kubeconfig kubeconfig-all-snapshots.json get ns
```

### Generating Findings

Generating findings leveraging the built-in queries:

```shell
java -jar replik8s.jar report --format json
```

This command supports the following options:
- `--format`: The report format (`json` or `xlsx`). Defaults to `xlsx`.
- `--snapshot-dir`: Directory of the snapshots to load. Defaults to `snapshots`.
- `--output-dir`: The directory to save the report to. Defaults to the current directory.

### Visualizing Snapshots

The following command starts a web server that serves an overview of the snapshot data:

```shell
java -jar replik8s.jar visualize
```

## Development

### Testing

To run the test suite, use the following command:

```shell
clj -X:test
```

### Formatting

This project uses `cljfmt` for code formatting. You can check the formatting of the codebase with:

```shell
clj -M:cljfmt check
```

And apply the correct formatting with:

```shell
clj -M:cljfmt fix
```

A pre-commit hook is also configured to automatically format your code before committing. To enable it, install `pre-commit` and run `pre-commit install` in the repository root.

## Build

Simply run:

```shell
clojure -T:build uber
```
