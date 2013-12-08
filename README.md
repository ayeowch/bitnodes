# Bitnodes
Bitnodes is currently being developed to estimate the size of the Bitcoin network by finding all the peering nodes in the network. The current methodology involves sending [getaddr](https://en.bitcoin.it/wiki/Protocol_specification#getaddr) message to find all the peering nodes in the network starting from a set of seed nodes. Bitnodes uses Bitcoin protocol version 70001, so nodes with older protocol version will be skipped.

## Requirements
* Python >= 2.7.1
* dig (or equivalent utility)
* SQLite >= 3.7.0 (to use WAL journal mode)

## Usage
The default configuration in bitnodes.conf should work for most users. To run Bitnodes:

    $ python bitnodes.py bitnodes.conf
    Writing output to bitnodes.log, press CTRL+C to terminate..

Newly discovered nodes will be added into a SQLite database called bitnodes.db in the `nodes` table.

## Database
Nodes data collected by Bitnodes are stored in a SQLite database called bitnodes.db. The database is created when Bitnodes runs for the first time. On subsequent run, the existing database will be renamed with .old extension and a new empty database will be created for the run.

`nodes` table contains all active nodes found during the run.
<table>
    <tr><th colspan="2">nodes</th></tr>
    <tr>
        <td>node</td>
        <td>port</td>
    </tr>
</table>

`nodes_version` table contains protocol version and user agent for nodes that Bitnodes has completed a Bitcoin protocol handshake with.
<table>
    <tr><th colspan="3">nodes_version</th></tr>
    <tr>
        <td>node</td>
        <td>protocol_version</td>
        <td>user_agent</td>
    </tr>
</table>

`nodes_getaddr` acts as the cache storage for bitnodes.Network.getaddr() function.
`data` field may contain JSON data with empty list, i.e. `[]`, or a list of known peers for the node.
If no JSON data is available, `null` (`None` in Python) is written into this field instead.
An error message is written into the `error` field if Bitnodes fails to establish connection with the node.
`degree` contains the number of known peers listed in `data`.
<table>
    <tr><th colspan="4">nodes_getaddr</th></tr>
    <tr>
        <td>node</td>
        <td>data</td>
        <td>error</td>
        <td>degree</td>
    </tr>
</table>

`jobs` table contains tracking information for each worker.
Each worker is assigned a seed node to start traversing the network.
The number of nodes found and network depth reached by this worker are stored in `added` and `depth` field respectively.
<table>
    <tr><th colspan="6">jobs</th></tr>
    <tr>
        <td>job_id</td>
        <td>started</td>
        <td>completed</td>
        <td>seed_ip</td>
        <td>added</td>
        <td>depth</td>
    </tr>
</table>

## License
Copyright (c) 2013 Addy Yeow Chin Heng &lt;ayeowch@gmail.com&gt;

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
