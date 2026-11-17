FreeRADIUS 4 changes the configuration format; nothing moves to it automatically (this image stays on 3.2).

Before moving, check each place that runs FreeRADIUS:

- [ ] this central image (the `rest` module `entra`, the generated `clients.conf` and `listen.conf`, the EAP-TTLS module; the entrypoint generates the two files)
- [ ] the site proxy image and the other site deployments, which send their requests here (their `proxy.conf` becomes `radius` modules)
- [ ] any other FreeRADIUS 3 deployment that shares this configuration style, such as firewall plugins
- [ ] read the upstream upgrade guide: `doc/antora/modules/howto/pages/upgrade/index.adoc`
