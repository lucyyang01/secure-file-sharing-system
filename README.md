# Secure File Sharing System

## Description 

This is my design and implementation of a client application for an end-to-end encrypted file sharing system secured with cryptography, similar to Dropbox. This system is secure against two threat models: a revoked user that becomes malicious, and an insecure database that can be tampered with.

The user authentication and authorization mechanisms support multiple user sessions, CRUD (Create, Read, Upload, Delete) operations, file sharing, file access control, and persistence of files across user sessions. This implementation leverages several cryptographic algorithms, such as public key encryption and digital signatures, to ensure data integrity and confidentiality. 

Rigorous security testing was conducted on this implementation to ensure protection against malicious users and operations, which can be found in the `client_test` directory.

## Design 

A detailed write up of the various cryptographic algorithms and data structures I used can be found in the design document. The diagram below illustrates the various data structures used and how they interact with each other.

TODO: INSERT DIAGRAM      

## Instructions for Use

## Collaborators

This project was completed with my partner, Joshua Kirby, as part of UC Berkeley's Computer Security course.

The full project specifications can be found here: https://cs161.org/proj2/
