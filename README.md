# HA-fusionpbx
##How to create a highly available fusionpbx cluster on Debian with keepalived postgresql and BDR

1. Create two machines with debian installs. Give both a public and private ip. Assign the security group fs-public to the public interface and fs-connect to the private interface.

Pre Checklist:
update hostname
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-hostname.html
generate ssh keys
add authorized_keys and config
set permissions
add ssh keys and config entry
test ssh between boxes

###Fusion1
2. On both servers run:

  ```
  apt-get update && apt-get upgrade -y
  apt-get install -y git
  cd /usr/src
  git clone https://github.com/fusionpbx/fusionpbx-install.sh.git
  chmod 755 -R /usr/src/fusionpbx-install.sh
  cd /usr/src/fusionpbx-install.sh/debian
  ```

Fusion 1
Edit the values
####/usr/src/fusionpbx-install.sh/debian/resources/config.sh
  ```
   domain_name=example.com
   database_repo=2ndquadrant
  ```
The BDR repositories and packages are needed for HA. Now do the install (/usr/src/fusionpbx-install.sh/debian/install.sh):

  ```
  ./install.sh
  ```
*Take note of the password you've been given in the output as the panel password.*
cat /etc/fusionpbx/config.php
*Take note of the password for the database.*


4. Add the following postgres conf files:
###/etc/postgresql/9.4/main/pg_hba.conf
Replace YOURSUBNET with the cidr of your subnet...
  ```
  local   all             postgres                                peer

  # TYPE  DATABASE        USER            ADDRESS                 METHOD

  # "local" is for Unix domain socket connections only
  local   all             all                                     peer
  # IPv4 local connections:
  host    all             all             127.0.0.1/32            md5
  #hostssl all             all             YOURSUBNET            trust # FOR SSL
  host all             all             YOURSUBNET            trust
  # IPv6 local connections:
  host    all             all             ::1/128                 md5
  # Allow replication connections from localhost, by a user with the
  # replication privilege.
  #local   replication     postgres                                peer
  host    replication     postgres        127.0.0.1/32            md5
  #host    replication     postgres        ::1/128                 md5
  #hostssl  replication     postgres        YOURSUBNET            trust # FOR SSL
  host  replication     postgres        YOURSUBNET              trust
  ```

###/etc/postgresql/9.4/main/postgresql.conf
  ```
  data_directory = '/var/lib/postgresql/9.4/main'        # use data in another directory
                      # (change requires restart)
  hba_file = '/etc/postgresql/9.4/main/pg_hba.conf'    # host-based authentication file
                      # (change requires restart)
  ident_file = '/etc/postgresql/9.4/main/pg_ident.conf'    # ident configuration file
                      # (change requires restart)

  external_pid_file = '/var/run/postgresql/9.4-main.pid'            # write an extra PID file
                      # (change requires restart)
  listen_addresses = '*'        # what IP address(es) to listen on;
                      # comma-separated list of addresses;
                      # defaults to 'localhost'; use '*' for all
                      # (change requires restart)
  port = 5432                # (change requires restart)
  max_connections = 100            # (change requires restart)
  unix_socket_directories = '/var/run/postgresql'    # comma-separated list of directories

  #ssl = true                # (change requires restart)
                      # (change requires restart)
  #ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'        # (change requires restart)
  #ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil-postgres.key'        # (change requires restart)

  shared_buffers = 128MB            # min 128kB
  dynamic_shared_memory_type = posix    # the default is the first option
  shared_preload_libraries = 'bdr'    # (change requires restart)

  max_worker_processes = 20
  wal_level = 'logical'            # minimal, archive, hot_standby, or logical
  max_wal_senders = 10        # max number of walsender processes

  max_replication_slots = 10    # max number of replication slots
  track_commit_timestamp = on    # collect timestamp of transaction commit

  log_error_verbosity = default
  log_min_messages = warning
  log_line_prefix = '%t [%p-%l] %q%u@%d '            # special values:

  log_timezone = 'localtime'

  stats_temp_directory = '/var/run/postgresql/9.4-main.pg_stat_tmp'

  datestyle = 'iso, dmy'
  timezone = 'localtime'
  default_text_search_config = 'pg_catalog.english'
  ```

5. Reboot the machine

6. Create the postgresql extensions on both databases:
  ```
  su -l postgres
  psql fusionpbx
  create extension btree_gist;
  create extension pgcrypto;
  create extension bdr;
  \connect freeswitch;
  create extension btree_gist;
  create extension pgcrypto;
  create extension bdr;
  ```

7. Create bdr group for fusionpbx and freeswitch databases, update t he ip with the private interface:
  ```
  \connect fusionpbx;
  SELECT bdr.bdr_group_create(local_node_name := 'fusion1', node_external_dsn := 'host=NODE1IP port=5432  dbname=fusionpbx connect_timeout=10 keepalives_idle=5 keepalives_interval=1');
  \connect freeswitch
  SELECT bdr.bdr_group_create(local_node_name := 'fusion1', node_external_dsn := 'host=NODE1IP port=5432  dbname=freeswitch connect_timeout=10 keepalives_idle=5 keepalives_interval=1');
  ```

Double check iptables on fusion 1 and the aws security groups, you will need to add the private subnet for postgres access.

###Fusion2

1. Add the necessary repos and keys (see commented line if you get gpg issues):
  ```
  echo 'deb http://apt.postgresql.org/pub/repos/apt/ stretch-pgdg main'  >> /etc/apt/sources.list
  echo 'deb http://packages.2ndquadrant.com/bdr/apt/ stretch-2ndquadrant main' >> /etc/apt/sources.list
  echo '#deb [trusted=yes] http://packages.2ndquadrant.com/bdr/apt/ stretch-2ndquadrant main' >> /etc/apt/sources.list
  /usr/bin/wget --quiet -O - http://apt.postgresql.org/pub/repos/apt/ACCC4CF8.asc | apt-key add -
  /usr/bin/wget --quiet -O - http://packages.2ndquadrant.com/bdr/apt/AA7A6805.asc | apt-key add -
  apt-get update && apt-get upgrade -y
  ```
2. Install the following packages
  ```
  sudo apt-get install postgresql-bdr-9.4 postgresql-bdr-9.4-bdr-plugin postgresql-bdr-contrib-9.4  
  ```

3. Create and setup the fusionpbx and freeswitch databases for BDR replication:
  ```
  sudo -u postgres psql -c "CREATE DATABASE fusionpbx";
  sudo -u postgres psql -c "CREATE DATABASE freeswitch";
  sudo -u postgres psql -c "CREATE ROLE fusionpbx WITH SUPERUSER LOGIN PASSWORD 'NODE1DBPASSWORD';"
  sudo -u postgres psql -c "CREATE ROLE freeswitch WITH SUPERUSER LOGIN PASSWORD 'NODE1DBPASSWORD';"
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE fusionpbx to fusionpbx;"
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE freeswitch to fusionpbx;"
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE freeswitch to freeswitch;"
  ```

4. Add the following config files replacing YOURSUBNET with your subnet in cidr notation (same as fusion1):
###/etc/postgresql/9.4/main/postgresql.conf
  ```
  data_directory = '/var/lib/postgresql/9.4/main'        # use data in another directory
                      # (change requires restart)
  hba_file = '/etc/postgresql/9.4/main/pg_hba.conf'    # host-based authentication file
                      # (change requires restart)
  ident_file = '/etc/postgresql/9.4/main/pg_ident.conf'    # ident configuration file
                      # (change requires resta##TODO
  rt)

  external_pid_file = '/var/run/postgresql/9.4-main.pid'            # write an extra PID file
                      # (change requires restart)
  listen_addresses = '*'        # what IP address(es) to listen on;
                      # comma-separated list of addresses;
                      # defaults to 'localhost'; use '*' for all
                      # (change requires restart)
  port = 5432                # (change requires restart)
  max_connections = 100            # (change requires restart)
  unix_socket_directories = '/var/run/postgresql'    # comma-separated list of directories

  #ssl = true                # (change requires restart)
                      # (change requires restart)
  #ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'        # (change requires restart)
  #ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil-postgres.key'        # (change requires restart)

  shared_buffers = 128MB            # min 128kB
  dynamic_shared_memory_type = posix    # the default is the first option
  shared_preload_libraries = 'bdr'    # (change requires restart)

  max_worker_processes = 20
  wal_level = 'logical'            # minimal, archive, hot_standby, or logical
  max_wal_senders = 10        # max number of walsender processes

  max_replication_slots = 10    # max number of replication slots
  track_commit_timestamp = on    # collect timestamp of transaction commit

  log_error_verbosity = default
  log_min_messages = warning
  log_line_prefix = '%t [%p-%l] %q%u@%d '            # special values:

  log_timezone = 'localtime'

  stats_temp_directory = '/var/run/postgresql/9.4-main.pg_stat_tmp'

  datestyle = 'iso, dmy'
  timezone = 'localtime'
  default_text_search_config = 'pg_catalog.english'
  ```
###/etc/postgresql/9.4/main/pg_hba.conf
  ```
  local   all             postgres                                peer

  # TYPE  DATABASE        USER            ADDRESS                 METHOD

  # "local" is for Unix domain socket connections only
  local   all             all                                     peer
  # IPv4 local connections:
  host    all             all             127.0.0.1/32            md5
  #hostssl all             all             YOURSUBNET            trust # FOR SSL
  host all             all             YOURSUBNET            trust
  # IPv6 local connections:
  host    all             all             ::1/128                 md5
  # Allow replication connections from localhost, by a user with the
  # replication privilege.
  #local   replication     postgres                                peer
  host    replication     postgres        127.0.0.1/32            md5
  #host    replication     postgres        ::1/128                 md5
  #hostssl  replication     postgres        YOURSUBNET            trust # FOR SSL
  host  replication     postgres        YOURSUBNET              trust
  ```

5. restart postgresql `service postgresql restart`

6. create db extensions for fusionpbx and freeswitch databases:
  ```
  su -l postgres
  psql fusionpbx
  create extension btree_gist;
  create extension pgcrypto;
  create extension bdr;
  \connect freeswitch;
  create extension btree_gist;
  create extension pgcrypto;
  create extension bdr;
  ```

7. On fusion2 join to the bdr group you've created on fusion1. NODE1IP is a management ip of node 1, preferrably a private ip
  ```
  \connect fusionpbx;
  select bdr.bdr_group_join(local_node_name := 'fusion2', node_external_dsn := 'host=NODE2IP port=5432 dbname=fusionpbx connect_timeout=10 keepalives_idle=5 keepalives_interval=1', join_using_dsn := 'host=NODE1IP  port=5432 dbname=fusionpbx connect_timeout=10 keepalives_idle=5 keepalives_interval=1');
  \connect freeswitch
  select bdr.bdr_group_join(local_node_name := 'fusion2', node_external_dsn := 'host=NODE2IP port=5432 dbname=freeswitch connect_timeout=10 keepalives_idle=5 keepalives_interval=1', join_using_dsn := 'host=NODE1IP  port=5432 dbname=freeswitch connect_timeout=10 keepalives_idle=5 keepalives_interval=1');
  ```

  You should see the fusionpx on fusion2 contains a number of tables after the join, as it has copied the tables from fusion1. If both joins succeeded replication is now happening between both nodes. *You can check to see that the join has succeeded by doing a `select bdr.bdr_node_join_wai1. t_for_ready();` on each database*. If it worked it will return, if it hangs, something has gone wrong.
  You can also see the status of the nodes in the group by doing: `select * from bdr.bdr_nodes;`
  Active replicating nodes have node status 'r'.
  Initializing nodes have node status 'i'.
  Dead/killed nodes have node status 'k'.


8. Now that fusion2 is in the bdr group we can install fusionpbx on fusion2. This way we still have a GUI if fusion1 goes down for some reason.
    ```
    cd /usr/src/fusionpbx-install.sh/debian
    ```
    Edit the install.sh file and comment out the postgres script
    ```
    #Postgres
    #resources/postgresql.sh
    ```
    Empty the finish script
    ```
    echo > resources/finish.sh
    ```
    Paste the script below into resources/finish.sh
    ```
    #!/bin/sh

    #move to script directory so all relative paths work
    cd "$(dirname "$0")"

    #includes
    . ./config.sh
    . ./colors.sh

    #database details
    database_username=fusionpbx
    if [ .$database_password = .'random' ]; then
      database_password=$(dd if=/dev/urandom bs=1 count=20 2>/dev/null | base64 | sed 's/[=\+//]//g')
    fi

    #allow the script to use the new password
    export PGPASSWORD=$database_password

    #install the database backup
    cp backup/fusionpbx-backup /etc/cron.daily
    cp backup/fusionpbx-maintenance /etc/cron.daily
    chmod 755 /etc/cron.daily/fusionpbx-backup
    chmod 755 /etc/cron.daily/fusionpbx-maintenance
    sed -i "s/zzz/$database_password/g" /etc/cron.daily/fusionpbx-backup
    sed -i "s/zzz/$database_password/g" /etc/cron.daily/fusionpbx-maintenance

    #add the config.php
    mkdir -p /etc/fusionpbx
    chown -R www-data:www-data /etc/fusionpbx
    cp fusionpbx/config.php /etc/fusionpbx
    sed -i /etc/fusionpbx/config.php -e s:"{database_host}:$database_host:"
    sed -i /etc/fusionpbx/config.php -e s:'{database_username}:fusionpbx:'
    sed -i /etc/fusionpbx/config.php -e s:"{database_password}:$database_password:"


    #get the server hostname
    if [ .$domain_name = .'hostname' ]; then
      domain_name=$(hostname -f)
    fi

    #get the ip address
    if [ .$domain_name = .'ip_address' ]; then
      domain_name=$(hostname -I | cut -d ' ' -f1)
    fi


    user_name=$system_username
    if [ .$system_password = .'random' ]; then
      user_password=$(dd if=/dev/urandom bs=1 count=20 2>/dev/null | base64 | sed 's/[=\+//]//g')
    else
      user_password=$system_password
    fi


    #restart freeswitch
    /bin/systemctl daemon-reload
    /bin/systemctl restart freeswitch

    #welcome message
    echo ""
    echo ""
    verbose "Installation Notes. "
    echo ""
    echo "   Please save the this information and reboot this system to complete the install. "
    echo ""
    echo "   Use a web browser to login."
    echo "      domain name: https://$domain_name"
    echo "      username: $user_name"
    echo "      password: $user_password"
    echo ""
    echo "   The domain name in the browser is used by default as part of the authentication."
    echo "   If you need to login to a different domain then use username@domain."
    echo "      username: $user_name@$domain_name";
    echo ""
    echo "   Official FusionPBX Training"
    echo "      Fastest way to learn FusionPBX. For more information https://www.fusionpbx.com."
    echo "      Available online and in person. Includes documentation and recording."
    echo ""
    echo "      Location:               Online"
    echo "      Admin Training:          TBA"
    echo "      Advanced Training:       TBA"
    echo "      Continuing Education:   https://www.fusionpbx.com/training"
    echo "      Timezone:               https://www.timeanddate.com/weather/usa/idaho"
    echo ""
    echo "   Additional information."
    echo "      https://fusionpbx.com/members.php"
    echo "      https://fusionpbx.com/training.php"
    echo "      https://fusionpbx.com/support.php"
    echo "      https://www.fusionpbx.com"
    echo "      http://docs.fusionpbx.com"
    echo ""
    ```
    Modify the following values in resources/config.sh
    ```
    domain_name=ip_address # same as fusion1
    system_username=admin  # same as fusion1
    system_password=random # same as fusion1
    database_password=random # same as fusion1
    database_repo=2ndquadrant #same as fusion1
    ```
    Run the install
    ```
    ./install.sh
    ```
    Update the iptables with the postgres access