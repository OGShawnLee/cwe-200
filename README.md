# CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## What is the weakness?

[CWE-200](https://cwe.mitre.org/data/definitions/200.html) happens when a product exposes sensitive information to an actor who is not authorized to see it. The information can be a secret, a credential, personal data, or anything else that is meant for one party only.

In this application, the sensitive information is the **security code** that grants access to the protected page. The code is supposed to be delivered only to the owner of a university (`@uv.mx`) account. The weakness lets someone who does not own that account receive it.

## The vulnerable code

The login flow has three files that matter.

`login.php` asks for an email address. `login.js` checks it on the client and then sends it to an external service:

```js
form.addEventListener("submit", (e) => {
  e.preventDefault();
  // ...
  if (!email.value.endsWith("@uv.mx")) {
    msg.classList.remove("d-none");
    // re-enable the form and stop
    return;
  }

  fetch("https://correocode.azurewebsites.net/correo", {
    method: "POST",
    body: JSON.stringify({
      correo: email.value,
    }),
    headers: {
      "Content-type": "application/json; charset=UTF-8",
    },
  }).then((json) => {
    document.location = "codigo.php";
  });
});
```

`codigo.php` asks for the code and grants access when it matches:

```php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
  if ($_POST["codigo"] == "7824") {
    $_SESSION["codigo"] = $_POST["codigo"];
    header("Location: index.php");
  }
}
```

`index.php` only checks that the session contains a `codigo` value.

### Why it is vulnerable

- **The domain check is only on the client.** `login.js` checks with `endsWith("@uv.mx")`, but a user can change or skip this JavaScript. The check is also a suffix test, so a value can satisfy it while containing more than one address.
- **The whole value is sent to the external service.** The server receives the raw `correo` string, not a validated single address. If the service splits the value on `;` or another separator, or simply delivers to every address it finds, the code is sent to an address the user does not own.
- **The example pattern.** An input of the form `victim@example.com;attacker@uv.mx` ends in `@uv.mx` and so passes the client check, but it names two recipients. The first recipient is not a `@uv.mx` account. The code is then delivered to a mailbox the person entering the value controls.
- **The code is static.** `codigo.php` compares against the constant `7824`. Anyone who receives that code by email can log in, so the email step is the only thing that limits access. Exposing the code to another mailbox is therefore enough to bypass the protection.
- **The client also ignores the response.** `login.js` moves to `codigo.php` after the request finishes, whether or not the service accepted the address.

Note that the external service (`correocode.azurewebsites.net`) is not in this folder, so I cannot see how it handles a value with a `;` in it. The exact recipients depend on that service. This is the part of the flow to confirm before you rely on the README's claim about where the code is sent.

## Lab use

Use this only in a lab you own or are authorized to test, and do not send codes to real addresses you are not allowed to use.

## The fix

Validate the address on the server, not only in the browser, and send the code only to a single, verified address:

```php
<?php
// Server-side check: exactly one address, in the allowed domain.
$correo = trim($_POST["correo"] ?? "");

if (!filter_var($correo, FILTER_VALIDATE_EMAIL) || !preg_match('/@uv\.mx$/i', $correo)) {
    http_response_code(400);
    exit("Correo no válido");
}

// Only now send the code to $correo, using the mail API your service provides.
```

Notes on the fix:

- `filter_var(..., FILTER_VALIDATE_EMAIL)` rejects values with extra recipients or separators, and the `preg_match` anchored to `$` checks the domain exactly. Do the check on the server, because a client check can be bypassed.
- Send to exactly the validated address and never pass the raw input to a service that interprets separators.
- Compare the code with `===` in `codigo.php`, and do not keep it hard-coded. Generate a one-time code for each login, store it server-side with an expiry time, and limit attempts.
- Return an error from the external service call and do not redirect when it fails.
- Remove the static `7824` value from the source; a secret in code is exposed to anyone with access to the repository.

## Verifying the bug and the fix

1. Enter a value that ends in `@uv.mx` but contains a second address, such as `victim@example.com;attacker@uv.mx`, and submit it.
2. Check where the external service sends the code. In the vulnerable version, the second-address mailbox may receive it, depending on the service.
3. With the server-side check in place, the same input should be rejected with an error and no code should be sent.

I have not run either version, so these results are what the code is expected to do, not observed output.

## Related weaknesses

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Exposure of Sensitive Information to an Unauthorized Actor (this document)
- [CWE-602](https://cwe.mitre.org/data/definitions/602.html): Client-Side Enforcement of Server-Side Security
- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials
