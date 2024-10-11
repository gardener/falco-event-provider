# Gardner Falco Event Provider

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

This component provides an interface for clients (Gardener Dashboard, command line) to retrieve stored Falco events. 

## Endpoints

verify user identity
Currently the provider offers two endpoints. To query either endpoint a valid JWT needs to be provided in the Authorization header:

```bash
Authorization: Bearer <token>
```

### Event endpoint

The event endpoint can be queried for events originating from one specific cluster belonging to a project of a landscape.

#### Endpoint url

The endpoint path consists of the landscape, project and cluster name. The cluster is optional and does not have to be provided.

``` bash
falco-provider/api/v1alpha1/events/<LANDSCAPE>/<PROJECT>/<CLUSTER>
```

#### Query parameters

An optional `filter` parameter can be provided. The `filter` is a JSON object with the following optional fields.

- `start` start time from which event shall be considered
- `end` end time from which event shall be considered
- `limit` number of events to return (maximum 1000)
- `offset` offset for paginated requests
- `hostnames` list of Kubernetes node names
- `priorities` list of Falco priorities
- `rules` list of Falco rules
- `ids` list of event ids

The `start` and `end` time define the direction of obtaining event. Per default the most current event will be provided first and the oldest event will be provided last. Time values need to be provided in ISO 8601 format.

#### Example request

```` bash
falco-provider/api/v1alpha1/events/sap-landscape-dev/garden/aws-ha?filter=%7B%22limit%22%3A+1%2C+%22start%22%3A+%222024-09-02T08%3A48%3A10.297213%2B00%3A00%22%2C+%22end%22%3A+%222024-09-03T08%3A48%3A10.297213%2B00%3A00%22%7D
````

#### Pagination

The `event` endpoint returns the events under the `response` field in the retured JSON object. If not all events could be retured in a single query (due to the total number of remaing events being larger than the `limit`), a `continueFilter` is also retured. This `filter` sets the offset accordingly and can this be used as the filter for a new request to obtain the next page of events. If all events defined by the filter could be retured in a response, no `continueFilter` is provided.

### Count endpoint

The count endpoint can be queried for a summary of event counts grouped by severity for all projects in a landscape.

#### Endpoint url

The endpoint path consists of the landscape.

``` bash
falco-provider/backend/api/v1alpha1/count/<LANDSCAPE>
```


#### Example request

``` bash
falco-provider/api/v1alpha1/count/sap-landscape-dev
```
