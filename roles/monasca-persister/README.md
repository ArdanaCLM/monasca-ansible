#monasca-persister
Installs the [monasca-persister](https://github.com/stackforge/monasca-persister) part of the [Monasca](https://wiki.openstack.org/wiki/Monasca) project.
There are two implementations of the persister, one Java based and one Python based. This will install the Java based one by default. To install
the python persister rather than the java version set the variable `monasca_persister_java` to False.

##Java Requirements

Requires Variables be defined for:
- zookeeper_hosts - A comma seperated list of kafka hosts with optional port
- kafka_hosts - A comma seperated list of kafka hosts with optional port
- influxdb_url
- influxdb_user
- influxdb_password

##Python Requirements

Requires Variables be defined for:
- zookeeper_hosts - A comma seperated list of kafka hosts with optional port
- kafka_hosts - A comma seperated list of kafka hosts with optional port
- influxdb_host
- influxdb_user
- influxdb_password

## Optional

- run_mode: One of Deploy, Stop, Install, Configure or Start. The default is Deploy which will do Install, Configure, then Start.

##Example Playbook

    hosts: monasca
    become: yes
    roles:
      - {role: tkuhlman.monasca-persister,
         kafka_hosts: "{{kafka_hosts}}",
         zookeeper_hosts: "{{zookeeper_hosts}}",
         influxdb_url: "http://{{mini_mon_host}}:8086",
         influxdb_user: "{{persister_influxdb_user}}",
         influxdb_password: "{{persister_influxdb_password}}",
         tags: [persister]}

##License
Apache

##Author Information
Tim Kuhlman
Monasca Team email monasca@lists.launchpad.net
