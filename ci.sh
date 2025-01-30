#/bin/bash

# Used to build the JAR file from our custom runner_image
# Using Debian Bookworm

# Install deps
apt update && apt install -y maven openjdk-17-jdk-headless

# Compile
mvn clean compile package

