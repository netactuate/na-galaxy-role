NetActuate Compute Node
=========

This role is for using the NetActuate Compute Node module

Requirements
------------

The only requirement besides Ansible is the Apache Lib Cloud module


Role Variables
--------------

List of required Role or Host variables

	state
		Desired state. One of [ present, running, stopped, terminated ]
	location
		Install location. ID or full name of location from portal.
	operating_system
		Install OS. ID or full name of OS from portal.
	ssh_public_key
		Path to your public key file.
	mbpkgid
		Package ID of purchased package to work with.
	hostname
		FQDN to set and identify host by.
	auth_token
		API key from settings page on portal.

Automatically set Variables
    ansible_host
        This is set from the role's task file by extracting it from the output
        of the module on a per host basis. This means you should have this role
        defined first in your playbooks.

Dependencies
------------

This role does not depend on any other roles, it is the base role to ensure
your OS is installed and running.

Example Playbook
----------------

This is the minimum you need in a playbook to ensure running state on all nodes in your inventory  
along with rest of the Role Variables above.


	- name: Running
	  hosts: all
	  remote_user: root
	  gather_facts: no
	  roles:
		- role: netactuate-compute-node
		  state: running

License
-------

GPLv2
