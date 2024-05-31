# Java 17 base image
FROM openjdk:17-jre-slim

# environment variables
ENV STEP_VERSION=0.21.0
ENV STEP_CA_PASSWORD="step_ca_password"

# Install dependencies and Smallstep CLI
RUN apt-get update && \
    apt-get install -y curl && \
    curl -L "https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}/step-cli_${STEP_VERSION}_amd64.deb" -o step-cli.deb && \
    curl -L "https://github.com/smallstep/certificates/releases/download/v${STEP_VERSION}/step-certificates_${STEP_VERSION}_amd64.deb" -o step-certificates.deb && \
    dpkg -i step-cli.deb && \
    dpkg -i step-certificates.deb && \
    rm step-cli.deb step-certificates.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create directories for Smallstep CA and certificates
RUN mkdir -p /etc/step-ca /etc/step-certificates

# Copy the Java application jar to the container
COPY your-java-application.jar /app/smallstep-ca.jar

# Expose the port your application runs on
EXPOSE 8080

# Volume to store certificates
VOLUME ["/etc/step-certificates"]

# Initialize Smallstep CA and generate certificates if not already present
CMD step ca init --name "My CA" --dns "localhost" --address ":443" --provisioner-password-file /dev/null && \
    if [ ! -f /etc/step-certificates/server.crt ]; then \
        step ca certificate "your-domain.com" /etc/step-certificates/server.crt /etc/step-certificates/server.key; \
    fi && \
    java -Djavax.net.ssl.keyStore=/etc/step-certificates/server.keystore -Djavax.net.ssl.keyStorePassword=your_password_here -jar /app/your-java-application.jar
