const everythingAlright = new Array(7).fill(false);
const regexLettersSmall = /^[a-ząćęłńóśźż]+$/;
const regexLettersSmallLatin = /^[a-z]+$/;
const regexLettersBig = /^[A-ZĄĆĘŁŃÓŚŹŻ]+$/;
const submit = document.getElementById("submit");
const PL = 'ĄĆĘŁŃÓŚŹŻ';
const pl = 'ąćęłńóśźż';
var originValue = null;

function checkValide(element, count, alert_element, message, valideFunction){
    if (!valideFunction(element.value)){
        markError(element, alert_element, count, message);
    } else {
        markAlright(element, alert_element, count);
    }
};

function markError(element, alert_element, count, message){
        element.className = "error";
        console.log(element.value + " has error");
        alert_element.className = "alert_error";
        alert_element.innerText = message;
        everythingAlright[count] = false;
        submit.setAttribute("disabled", "");
};

function markAlright(element, alert_element, count) {
        element.className = "alright";
        alert_element.className = "alert_alright";
        everythingAlright[count] = true;
        if(everythingAlright.every((v) => v === true)){
            submit.removeAttribute("disabled");
        }
};

function valideName(value){
     if (value.length > 40)
         return false;
     if (!regexLettersBig.test(value[0]))
         return false;
     if (!regexLettersSmall.test(value.slice(1, value.length)))
         return false; 
     return true;

};


function valideGender(value){
    if (value === 'M' || value === 'F') {
        return true;
    } else {
        return false;
    }
};

function valideLogin(value){
    return value.length > 3 && value.length < 12 && regexLettersSmallLatin.test(value);
}

function validePassword(value){
    return ((value.length >= 8) && (value.length <=40)) ? true : false;
};

function valideSecondPassword(value){
    return value === originValue;
};

function valideAvatar(value){
    let extension = value.split('.').pop();
    let allowedExtensions = ["png", "jpg"];
    console.log(allowedExtensions, extension);
    if (allowedExtensions.includes(extension)){
        return true;
    } else {
        return false;
    }
};



function attach_events(){


    const alert_name = document.getElementById("alert_name");
    const firstname = document.getElementById("firstname");
    firstname.addEventListener("change", function(ev){
        let message = "Name should start with big letter and contain only letters";
        checkValide(firstname, 0, alert_name, message, valideName);
    });


    const alert_lastname = document.getElementById("alert_lastname");
    const lastname = document.getElementById("lastname");
    lastname.addEventListener("change", function(ev){
        let message = "Last name should start with big letter and contain only letters";
        checkValide(lastname, 1, alert_lastname, message, valideName);
    });
   
    
    const alert_username = document.getElementById("alert_username");
    const username = document.getElementById("login");
    username.addEventListener("change", function(ev){
        let message = "Username is taken";
        let value = username.value;
        let xhr = new XMLHttpRequest();
        let request = 'https://infinite-hamlet-29399.herokuapp.com/check/' + value;
        xhr.onreadystatechange = function(){
            let DONE = 4;
            let OK = 200;
            if (xhr.readyState == DONE){
                if(xhr.status == OK){
                    let response = JSON.parse(xhr.responseText);
                    if ((response[value] === "available") && valideLogin(value) ){
                        markAlright(username, alert_username, 2);
                    } else {
                        markError(username, alert_username, 2, message);
                    }
                } 
            }
        };
        console.log(request);
        xhr.open('GET', request, true);
        xhr.send(null);
        
    });
    
    everythingAlright[3] = true;
    
    const alert_pass = document.getElementById("alert_pass");
    const pass1 = document.getElementById("password");
    pass1.addEventListener("change", function(ev){
        originValue = pass1.value;
        let messageFirst = "Password should contain at least 8 symbols and less than 40";
        let messageSecond = "Password does not match"
        checkValide(pass1, 4, alert_pass, messageFirst, validePassword); 
        checkValide(pass2, 5, alert_pass2, messageSecond, valideSecondPassword)
    });
    
    const alert_pass2 = document.getElementById("alert_pass2");
    const pass2 = document.getElementById("password_second");
    pass2.addEventListener("change", function(ev){
        originValue = pass1.value;
        let message = "Password does not match";
        checkValide(pass2, 5, alert_pass2, message, valideSecondPassword);
    });
    // Synchronize both passwords
    
    
    const alert_avatar = document.getElementById("alert_avatar");
    const avatar = document.getElementById("photo");
    avatar.addEventListener("change", function(ev){
        let message = "Wrong extension";
        checkValide(avatar, 6, alert_avatar, message, valideAvatar);
    });
    

};


attach_events();
