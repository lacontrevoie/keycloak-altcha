#/bin/bash

# Used to build the JAR file from our custom runner_image
# Using Debian Bookworm

# Install deps
apt update && apt install -y maven openjdk-17-jdk-headless

# Move to the right folder in CI
cd /run_dir

# Compile
mvn clean compile package

