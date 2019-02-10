# ELK config for GoBittrex

To get logs in Kibana we need logstash config like below

```
input {
  file {
    path => [ "/var/log/system.log", "/var/log/messages", "/var/log/syslog" ]
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" and [syslog_program] == "gobittrex-notice" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["127.0.0.1:9200"]
    index => "gobittrex-log"
  }
  stdout { codec => rubydebug }
}
```
which needs to be added to 
```
$sudo vim /etc/logstash/conf.d/gobittrex.conf
$brew services restart logstash
$logstash -f gobittrex.conf 
```


Above should create index visible on
```
http://localhost:9200/gobittrex-log
http://localhost:5601
```

Above logs will be written with the code similar to:
```
l, err := syslog.New(syslog.LOG_NOTICE, "gobittrex-notice")
if err == nil {
  log.SetOutput(l)
}

log.Println("GoBittrex app started")
```

When using custom logs mappings can be pushed via **Kibana Dev Tools** with whatever structure to parse logs written to **custom logs** 

```
PUT gobittrex-notice
{
	"mappings": {
		"doc": {
			"properties": {
				"handle": {
					"type": "text"
				},
				"received_at": {
					"type": "text"
				},
        "host": {
					"type": "text"
				},
        "message": {
					"type": "text"
				}
			}
		}
	}
}
```

and checked with
```
GET /_cat/indices?v
```

We can delete indices with
```
DELETE /gobittrex-notice
```


```
hostname, err := os.Hostname()
if err != nil {
	panic(err)
}

f, err := os.OpenFile("gobittrex.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
if err != nil {
	log.Println(err)
}

logger := log.New(f,"NOTICE: ", log.Ldate|log.Ltime|log.Lshortfile)
logger.Println(hostname + " " +"GoBittrex app started")
```
