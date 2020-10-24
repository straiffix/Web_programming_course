/**
 * Callback triggered when input validation status changes
 *
 * @callback validationChangeHandler
 * @param {bool} valid true if input is valid, false otherwise
 */

/**
 * Function to check if field value is valid
 *
 * @callback validationCheck
 * @param {string} value input value
 * @returns {bool} true if value is valid, false otherwise
 */

/**
 * 
 * @param {HTMLInputElement} input input that will be validated
 * @param {string} errorMessage 
 * @param {validationCheck} validationCheck
 * @param {validationChangeHandler} validationChangeHandler 
 */
const addValidation = (input, validationCheck, errorMessage, validationChangeHandler) => {
    const alert = input.parentElement.querySelector("[data-alert]");
    alert.innerText = errorMessage;

    input.addEventListener("change", async () => {
        const valid = await validationCheck(input.value);

        alert.hidden = valid;
        input.classList.toggle("alright", valid);
        input.classList.toggle("error", !valid);
        validationChangeHandler(valid); // This could be triggered only when new state is different from previous one
    });
}

function attach_events() {
    const everythingAlright = new Array(6).fill(true);

    const validationStatusChanged = (i, newValue) => {
        const submit = document.getElementById("submit");

        everythingAlright[i] = newValue;
        const ok = everythingAlright.every((v) => v === true);
        submit.disabled = !ok;
    };

    addValidation(
        document.getElementById("textname"),
        (value) => !/\d/.test(value),
        "Wrong name. Should contain only letters",
        (valid) => validationStatusChanged(0, valid)
    );

    addValidation(
        document.getElementById("textlastname"),
        (value) => !/\d/.test(value),
        "Wrong name. Should contain only letters",
        (valid) => validationStatusChanged(1, valid)
    );

    const validateUsername = async (username) => {
        const baseUlr = 'https://infinite-hamlet-29399.herokuapp.com/check';
        const response = await fetch(`${baseUlr}/${username}`);
        const data = await response.json();
        console.log(data);
        return data[username] === "available";
    }

    addValidation(
        document.getElementById("textusername"),
        validateUsername,
        "Username already taken",
        (valid) => validationStatusChanged(2, valid)
    );

    const validateAvatar = (fileName) => {
        let extension = fileName.split('.')[1];
        const allowedExtensions = new Set(['png', 'jpg']);
        return allowedExtensions.has(extension);
    };

    addValidation(
        document.getElementById("avatar"),
        validateAvatar,
        "Wrong extension",
        (valid) => validationStatusChanged(5, valid)
    );
}


attach_events() 
