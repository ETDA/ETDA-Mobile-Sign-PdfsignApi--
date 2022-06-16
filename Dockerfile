#
# Build stage
#
FROM maven:3.8.1-openjdk-15-slim AS build
COPY ./src /home/app/src
COPY ./pom.xml /home/app
RUN mvn -f /home/app/pom.xml -X -e clean package

#
# Package stage
#
FROM openjdk:15.0.2-jdk-oracle
RUN mkdir /var/config/
RUN microdnf update -y && microdnf install -y git cronie
COPY --from=build /home/app/target/PdfSignerAPI-0.0.1.jar /opt/PdfSigner/PdfSignerAPI.jar
COPY ./resources/conf /var/config/PdfSigner
COPY ./resources/PKCS12/PdfSigner.p12 /var/config/PdfSigner/PdfSigner.p12

ENV TZ="Asia/Bangkok"

# Run the JAR file
CMD ["java","-jar","/opt/PdfSigner/PdfSignerAPI.jar"]
