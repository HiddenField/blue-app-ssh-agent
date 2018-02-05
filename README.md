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
  # This is required for USB support
  brew cask install virtualbox-extension-pack
  brew cask install vagrant

  ```

2. Clone the [ledger-vagrant](https://github.com/fix/ledger-vagrant) project and bring up the vagrant machine:

    ```bash
    git clone git@github.com:fix/ledger-vagrant.git
    cd ledger-vagrant
    vagrant up
    ```
3. Clone the application onto you machine

    ```bash
    # Where the application is cloned to is called LEDGER_CARDANO_HOME
    # For testers and developers we would advise you to clone straight into the Vagrant VM's app folder      
    git clone [CLONE_URL_OF_GIT_REPOSITORY]
    ```

4. Copying your code into the VM is done via the `apps` directory which is synced in Vagrant:

	```bash
	cd ledger-vagrant
	cp -r [LEDGER_CARDANO_HOME] ./apps/
	```

5. SSH into the Vagrant VM

	```bash
	# get the ID of the machine first
	vagrant global-status
	vagrant ssh <ID>
  # You are now on the VM - note the prompt change
  vagrant@vagrant-ubuntu-trusty-64:~$
	```

6. Setup Custom CA - These commands are run inside the Vagrant VM (vagrant@vagrant-ubuntu-trusty-64:~$)

  To remove the user warnings when installing, running and deleting the app from the Ledger device, you need to generate a Custom CA keypair.

  ```bash
  cd ~/apps/ledger-cardano-app
  python -m ledgerblue.genCAPair
  ```

  This command will output the keypair onto the screen. Highlight the private key (after the colon) - Command + C

  ```
  Public key : 04180cf57eb2afc56ea26cc13a3a01839943a03b40d32110d401553a78a814b40b3c863f96e04f9a7710335fe920b3d0bec21529480341b381b21d7bc617b02160
  Private key: d30b3e3d25dc84cec995d1163b21a970e32879a728eccf29fd455b9a70cbc3d1
  ```

  Save private key into file sign.key in root directory
  ```bash
  touch sign.key
  echo [PASTE PRIVATE KEY] > sign.key
  cat sign.key
  # You should see the output of the private key
  d30b3e3d25dc84cec995d1163b21a970e32879a728eccf29fd455b9a70cbc3d1
  ```

  Load public key onto Ledger device:

  ```bash
  cd ~/apps/ledger-cardano-app
  python -m ledgerblue.setupCustomCA --targetId 0x31100002 --public [PUBLIC KEY]  
  ```  

7. To deploy, simply run:

	```bash    
	vagrant@vagrant-ubuntu-trusty-64:~$ cd apps/ledger-cardano-app
  # Delete the current application if you are testing/building a different version
  vagrant@vagrant-ubuntu-trusty-64:~$ make delete
  # Build and load the application onto the Nano S
	vagrant@vagrant-ubuntu-trusty-64:~$ make clean load
	```
8. To build test build and deploy:

  ```bash    
  # Same as normal build above, but instead:
  vagrant@vagrant-ubuntu-trusty-64:~$ make clean test
  ```

9. Shutdown VM - You must exit the VM in order for the host machine to regain visibility of the Ledger device.

  ```bash
  vagrant@vagrant-ubuntu-trusty-64:~$ exit
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

* When the Vagrant VM is running you do not have access to the Ledger device on the host machine. You need to shutdown the VM first.

[1] *Note that this is because Docker for Mac does not support USB connectivity due to [xhyve limitations](https://github.com/mist64/xhyve#what-is-bhyve)*

## Deploying

The build process is managed with [Make](https://www.gnu.org/software/make/).

### Make Commands

* `clean`: Clean the build and output directories
* `delete`: Remove the application from the device
* `load`: Load signed app onto the Ledger device with regular api
* `test`: Load signed app onto the Ledger device with test api
* `build`: Build obj and bin api artefacts without loading
* `build-test`: Build obj and bin test api artefacts without loading
* `sign`: Sign current app.hex with CA private key
* `deploy`: Load the current app.hex onto the Ledger device

See `Makefile` for list of included functions.

### Deploying Development API

`make clean load`

Use clean when switching between development and testing APIs to ensure correct interfaces are built.

### Deploying Test API

`make clean test`

### Deploying Release

Releases will need to be given to Ledger for signing with their private key.
This will allow the application to be installed without warning prompts on any Ledger device.
