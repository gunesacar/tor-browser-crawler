# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "tknerr/baseimage-ubuntu-14.04"

  config.vm.provider "virtualbox" do |v, override|
    override.vm.box = "debian/jessie64"
  end

  digital_ocean_config = (JSON.parse(File.read("digital-ocean-machines.json")))
  digital_ocean_config['droplets'].each do |instance|
    droplet_name   = instance[0]
    droplet_value = instance[1]

    config.vm.provider :digital_ocean do |droplet, override|
        override.vm.box = 'digital_ocean'
        override.vm.box_url = "https://github.com/devopsgroup-io/vagrant-digitalocean/raw/master/box/digital_ocean.box"
        override.ssh.username = digital_ocean_config['ssh_username']
        override.ssh.private_key_path = digital_ocean_config['ssh_private_key_path']
        droplet.token = digital_ocean_config['token']

        override.vm.hostname = droplet_name
        droplet.image = droplet_value['image']
        droplet.region = droplet_value['region']
        droplet.size = droplet_value['ram_size']
    end
  end

  config.vm.synced_folder "./", "/home/vagrant/tor-browser-crawler/", disabled: false
  config.vm.synced_folder "./tor", "/home/vagrant/tor/", disabled: false
  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "playbook.yml"
  end
end
