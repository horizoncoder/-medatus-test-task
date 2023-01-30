# Introduction

Foremost, thank you for your participation. We are a small startup with limited resources, but we have ambitious plans and even bigger dreams. Our goal is to change the way how people and healthcare service provider connect with each other. To achieve that, we require developers who are highly motivated and have a solid foundation of knowledge for our required technology stack. Once again, thank you for your participation.

# Task:
Your objective is to implement a Rest API that manages registration, login, and change password functionality.

## Task summary:
The following is a brief description of the needed functionality. To understand what technical details the implementation has to cover, please take a look at the  below.

### Registration
A user can register (`POST: { username: string, password: string }` at `/register`) an account by providing a valid email address and a password. If the registration is valid, meaning the user's email and password were accepted, a correct response as a `json` object will be given.

### Login
They can log in (`POST: { username: string, password: string }` at `/login`). If successfully logged in, a session is returned.

### Password change
User can change its current password (`POST: { session: object, oldPassword: string, newPassword: string }` at `/user/change-password`). If changing the password is successful, the current session will be revoked and the user as to login again.

#### Server Response:
The server response - even for failure - should be of this form: `{ requestObject: any, message: string}`.
### Tools

#### Nest.js
Please consider using the boilerplate `nest.js` project from this repository and align to the best practices of implementation right from the official `nest.js` documentation page! This project is not complicated to be implemented, but it offers us a great way to see how you utilize existing technology, understand when to use `controllers`, `providers`, `middleware`, `pipes`, `guards` and `interceptors`.

### Optional
If you want to show us that you really care about performance, implement this task by telling `nest.js` to use `Fastify` by using `nests` `FastifyAdapter` framework adapter.

#### MongoDB
Please consider using MongoDB as your database solution. Furthermore, with the project, there is a `docker-compose.yaml` file to easily set up a MongoDB instance to work with. Again – also refer to the official documentation how to use best practices for `nest.js` to communicate with MongoDB. If you do not have docker, or you are already hosting a MongoDB instance of some kind, that is no problem. You are free to do so, but please update the `user` and `password` field within the `docker-compose.yaml` file, so we can easily spin up our test stack with the correct credentials used within your implementation.

# General Architecture Guidelines
The following guidelines are part of the implementation requirements. Please utilize available node.js modules to achieve the desired behavior, document what functionality you utilize from external and what functionality has been added by you.

## Authentication

### User IDs
Make sure your usernames/user IDs are case-insensitive. User 'smith@gmail.com' and user 'Smith@gmail.com' should be the same user. Usernames should also be unique, and therefore we will use the email address as the username.

#### Username validation
Properly parsing email addresses for validity with regular expressions is very complicated.

The biggest caution on this is that although the RFC defines a very flexible format for email addresses, most real-world implementations (such as mail servers) use a far more restricted address format, meaning that they will reject addresses that are technically valid. Although they may be technically correct, these addresses are of little use if your application will not be able to actually send emails to them. Your implementation has to check for the following facts:

- The email address contains two parts, separated with an `@` symbol.
- The email address does not contain dangerous characters (such as backticks, single or double quotes, or null bytes).
  - Exactly which characters are dangerous will depend on how the address will be used (echoed in page, inserted into database, etc.).
- The domain part contains only letters, numbers, hyphens (`-`) and periods (`.`).
- The email address is a reasonable length:
  - The local part (before the `@`) should be no more than `63` characters.
  - The total length should be no more than `254` characters.

In a real application, the semantic validation is about determining whether the email address is correct and legitimate. The most common way to do this is to email the user, and require that they click a link in the email, or enter a code that has been sent to them. Semantic validation is not part of this implementation.

### Proper Password Strength Controls
A key concern when using passwords for authentication is password strength. A “strong” password policy makes it difficult or even improbable for one to guess the password through either manual or automated means. The following characteristics define a strong password and need to be implemented:

- Password Length
- Minimum length of the passwords should be enforced by the application. Passwords shorter than 8 characters are considered to be weak (NIST SP800-63B).
- Maximum password length should not be set too low, as it will prevent users from creating passphrases. A common maximum length is `64` characters due to limitations in certain hashing algorithms. It is important to set a maximum password length to prevent long password Denial of Service attacks.
- Password rotation for every `180` days after login.
- It is essential to store passwords in a way that prevents them from being obtained by an attacker even if the application or database is compromised. The majority of modern languages and frameworks provide built-in functionality to help store passwords safely.
After an attacker has acquired stored password hashes, they can always brute force hashes offline. As a defender, it is only possible to slow down offline attacks by selecting hash algorithms that are as resource intensive as possible. So for this task implement the password hash using `bcrypt`, use a work factor of `10` or more and with a password limit of `72` bytes.
- Include password strength meter to help users create a more complex password and block common and previously breached passwords by using the great [zxcvbn](https://github.com/zxcvbn-ts/zxcvbn) library.

### Session Management
To keep the authenticated state and have the ability to change the password, the application will provide a session identifier. While implementing this functionality, please keep in mind the following facts:

- The name used by the session ID should not be extremely descriptive nor offer unnecessary details about the purpose and meaning of the ID.
- The session ID must be long enough to prevent brute force attacks, where an attacker can go through the whole range of ID values and verify the existence of valid sessions. The session ID length must be at least `128 bits (16 bytes)`.

- The session ID must be unpredictable (random enough) to prevent guessing attacks, where an attacker can guess or predict the ID of a valid session through statistical analysis techniques. For this purpose, a good [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) (Cryptographically Secure Pseudorandom Number Generator) must be used.
- The session ID value must provide at least `64 bits` of entropy (if a good PRNG is used, this value is estimated to be half the length of the session ID).
- Additionally, a random session ID is not enough; it must also be unique to avoid duplicated IDs. A random session ID must not already exist in the current session ID space.
- The session ID content (or value) must be meaningless to prevent information disclosure attacks, where an attacker is able to decode the contents of the ID and extract details of the user, the session, or the inner workings of the web application.
- The meaning and business or application logic associated with the session ID must be stored on the server side, and specifically, in session objects or in a session management database or repository.
