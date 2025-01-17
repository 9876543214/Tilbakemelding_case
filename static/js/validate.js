const validation = new JustValidate("#signup");

validation
    .addField("#name", [
        {
            rule: "required"
        }
    ])
    .addField("#email", [
        {
            rule: "required"
        },
        {
            rule: "email"
        },
        {
            validator: (value) => () => {
                return fetch("validate_email?email=" + encodeURIComponent(value))
                       .then(function(response) {
                           return response.json();
                       })
                       .then(function(json) {
                           return !json.exists;
                       });
            },
            errorMessage: "Email already in use"
        }
    ])
    .addField("#password", [
        {
            rule: "required"
        },
        {
            rule: "password"
        }
    ])
    .addField("#password_confirmation", [
        {
            validator: (value, fields) => {
                return value === fields["#password"].elem.value;
            },
            errorMessage: "Passwords should match"
        }
    ])
    .onSuccess((event) => {
        document.getElementById("signup").submit();
    });
