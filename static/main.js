const everythingAlright = new Array(6).fill(false);
const regexLettersSmall = /^[a-z]+$/;
const regexLettersBig = /^[A-Z]+$/;
const submit = document.getElementById("submit");
var originValue = null;

function checkValide(
        element,
        count,
        alert_element,
        message,
        valideFunction){
    if (!valideFunction(element.value)){
        /*element.className = "error";
        console.log(element.value + "error");
        alert_element.className = "alert_error";
        alert_element.innerText = message;
        everythingAlright[count] = false;
        submit.setAttribute("disabled", "");*/
        markError(element, alert_element, count, message);
    }
    else{
        /*element.className = "alright";
        alert_element.className = "alert_alright";
        everythingAlright[count] = true;
        if(everythingAlright.every((v) => v === true)){
            submit.removeAttribute("disabled");
        }*/
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

}

function markAlright(element, alert_element, count) {
        element.className = "alright";
        alert_element.className = "alert_alright";
        everythingAlright[count] = true;
        if(everythingAlright.every((v) => v === true)){
            submit.removeAttribute("disabled");
        }

}

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
        let message = "taken";
        let value = username.value;
        let xhr = new XMLHttpRequest();
        let request = 'https://infinite-hamlet-29399.herokuapp.com/check/' + value;
        xhr.onreadystatechange = function(){
            let DONE = 4;
            let OK = 200;
            if (xhr.readyState == DONE){
                if(xhr.status == OK){
                    let response = JSON.parse(xhr.responseText);
                    if (response[value] === "available"){
                        markAlright(username, alert_username, 2);
                        /*alert_username.style.display = "none";
                        username.className = "alright";
                        everythingAlright[2] = true;
                        if(everythingAlright.every(function(check){return check===true})){
                            submit.removeAttribute("disabled");
                        }*/
                    } else {
                        markError(username, alert_username, 2, message);
                        /*alert_username.style.display = "block";
                        username.className = "error";
                        alert_username.innerHTML = "Taken";
                        everythingAlright[2] = false;
                        submit.setAttribute("disabled", "");*/
                        
                    }
                } else {
                    alert_username.style.display = "block";
                    username.className = "Cannot connect";
                    
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
        let message = "Password should contain at least 8 symbols and less than 40";
        checkValide(pass1, 4, alert_pass, message, validePassword); 
    });
    
    const alert_pass2 = document.getElementById("alert_pass2");
    const pass2 = document.getElementById("password_second");
    pass2.addEventListener("change", function(ev){
        var originValue = pass1.value;
        let message = "Password does not match";
        checkValide(pass2, 5, alert_pass2, message, valideSecondPassword);
    });
    
    
    const alert_avatar = document.getElementById("alert_avatar");
    const avatar = document.getElementById("photo");
    avatar.addEventListener("change", function(ev){
        let message = "Wrong extension";
        checkValide(avatar, 6, alert_avatar, message, valideAvatar);
    });
    

}


attach_events() 
