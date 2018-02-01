# Cardano App

> A simple Cardano SL app for Ledger Nano S, supporting ed25519 derivation and keys.

## Compatibility

This app is compatible with [this fork](https://github.com/HiddenField/cardano-ledger-node-js-api) of the **cardano-ledger-node-js-api** client.

## Current Instruction Set

| Get Public Key for a given derivation path | INS_GET_PUBLIC_KEY | 0x02 |
| Generate random public key on 44'/1815'/[WALLET_INDEX]'/0'| INS_GET_RND_PUB_KEY | 0x0C |
| Calculates and returns the Wallet Index | INS_GET_WALLET_INDEX | 0x0E |

## APDU Breakdown

See [doc/cardanoapp.asc](doc/cardanoapp.asc)

## Building

Environment setup and developer documentation is succinctly provided in Ledger’s [Read the Docs](http://ledger.readthedocs.io/en/latest/). Fix’s Vagrant project is also very useful for setting up development environments off linux using [Ledger Vagrant](https://github.com/fix/ledger-vagrant).

### Mac OSX

To set up your environment on Mac, using [Vagrant](https://www.vagrantup.com) is recommended^[1].


1. Install [VirtualBox](https://www.virtualbox.org/) and [Vagrant](https://www.vagrantup.com/):

  ```bash
  brew cask install virtualbox
  # This is required for USB suppor
  brew cask install virtualbox-extension-pack
  brew cask install vagrant

  ```

2. Clone the [ledger-vagrant](https://github.com/fix/ledger-vagrant) project and bring up the vagrant machine:

    ```bash
    git clone git@github.com:fix/ledger-vagrant.git
    cd ledger-vagrant
    vagrant up
    ```
3. Copying your code into the VM is done via the `apps` directory which is synced in Vagrant:

	```bash
	cd ledger-vagrant
	cp -r <location>/ledger-cardano-app ./apps/
	```

4. SSH into the Vagrant VM

	```bash
	# get the ID of the machine first
	vagrant global-status
	vagrant ssh <ID>
	```
5. To deploy, simply run:

	```bash
	cd apps/ledger-cardano-app
	make load
	```
#### Known Issues

* At present, the Vagrant setup does not include adding the ARM toolchain to the path, which is required for compilation. This can be resolved by adding the following to `~/.bashrc`:

	```bash
	export ARM_HOME=/opt/bolos/gcc-arm-none-eabi-5_3-2016q1
	export PATH=$PATH:$ARM_HOME/bin
	```
* There is an issue with [ledgerblue](https://github.com/LedgerHQ/blue-loader-python) 0.1.16 which causes installation to fail. If this occurs, simply install 0.1.15 using the following:

	```bash
	sudo pip uninstall ledgerblue
	# Or, if this fails, remove manually:
	rm -rf /usr/local/lib/python2.7/dist-package/ledgerblue*

	sudo pip install ledgerblue==0.1.15
	```

[1] *Note that this is because Docker for Mac does not support USB connectivity due to [xhyve limitations](https://github.com/mist64/xhyve#what-is-bhyve)*

## Deploying

The build process is managed with [Make](https://www.gnu.org/software/make/).

### Setting Up Custom CA for signing Ledger App

To remove the prompts when installing, running and deleting the app from the Ledger device, you need to generate a Custom CA keypair.

* `python -m ledgerblue.genCAPair` outputs key pair onto screen
* Save private key into file sign.key in root directory
* Load public key onto Ledger device:
* `python -m ledgerblue.setupCustomCA --targetId 0x31100002 --public [PUBLIC KEY]`

The private key held in sign.key is required in the make commands below.

### Make Commands

* `clean`: Clean the build and output directories
* `delete`: Remove the application from the device
* `load`: Load the app onto the Ledger device with regular api
* `test`: Load the app onto the Ledger device with test api
* `build`: Build obj and bin api artefacts without loading
* `build-test`: Build obj and bin test api artefacts without loading
* `sign`: Sign current app.hex with CA private key
* `deploy`: Load the current app.hex onto the Ledger device

See `Makefile` for list of included functions.

### Deploying Development API

`make clean build sign deploy`

### Deploying Test API

`make clean test sign deploy`

### Deploying Release

Releases will need to be given to Ledger for signing with their private key.
This will allow the application to be installed without warning prompts on any Ledger device.
