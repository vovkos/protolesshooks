if [[ "$TRAVIS_OS_NAME" == "linux" && "$TARGET_CPU" == "x86" ]]; then
	sudo dpkg --add-architecture i386
	sudo apt-get -qq update
	sudo apt-get install -y g++-multilib
fi
