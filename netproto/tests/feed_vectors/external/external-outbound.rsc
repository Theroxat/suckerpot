# selfhostr external-outbound serial 4812 generated 2026-11-01T13:00:00Z licence CC0-1.0 source abuse.ch Feodo Tracker. Not confirmed by the SuckerPot network.
:local t 1d6h
/ip firewall address-list
:do { add list=selfhostr-external-outbound address=192.0.2.77 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-external-outbound address=192.0.2.77] timeout=$t }
:do { add list=selfhostr-external-outbound address=198.51.100.9 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-external-outbound address=198.51.100.9] timeout=$t }
:do { add list=selfhostr-external-outbound address=203.0.113.45 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-external-outbound address=203.0.113.45] timeout=$t }
/ipv6 firewall address-list
:do { add list=selfhostr-external-outbound address=2001:db8::45/128 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-external-outbound address=2001:db8::45/128] timeout=$t }
