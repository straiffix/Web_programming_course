const everythingAlright = new Array(6).fill(false);
const regexLetters = /^[a-zA-Z]+$/;
const submit = document.getElementById("submit");
var originValue = null;

function checkValide(
        element,
        count,
        alert_element,
        message,
        valideFunction){
    if (!valideFunction(element.value)){
        
        element.className = "error";
        alert_element.style.display = "block";
        alert_element.innerText = message;
        everythingAlright[count] = false;
        submit.setAttribute("disabled", "");
    }
    else{
        element.className = "alright";
        alert_element.style.display = "none";
        everythingAlright[count] = true;
        if(everythingAlright.every((v) => v === true)){
            submit.removeAttribute("disabled");
        }
    }

};

function valideName(value){
     return regexLetters.test(value);
    };

function valideUsername(value){
        let xhr = new XMLHttpRequest();
        let request = 'https://infinite-hamlet-29399.herokuapp.com/check/' + value;
        xhr.onreadystatechange = function(){
            let DONE = 4;
            let OK = 200;
            if (xhr.readyState == DONE){
                if(xhr.status == OK){
                    let response = JSON.parse(xhr.responseText);
                    if (response[value] === "available"){
                        return true;
                }
                    } else {
                        return false;
                        
                    }
                } else {
                    return false;
                    
                }
            }
        console.log(request);
        xhr.open('GET', request, true);
        xhr.send(null);
};

function valideGender(value){
    if (value === 'M' || value === 'F') {
        return true;
    } else {
        return false;
    }
}

function validePassword(value){
    return value.length >= 8 ? true : false;
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

    everythingAlright[3] = true;

    const alert_name = document.getElementById("alert_name");
    const firstname = document.getElementById("firstname");
    firstname.addEventListener("change", function(ev){
        let message = "Name can contain only letters";
        checkValide(firstname, 0, alert_name, message, valideName);
    });


    const alert_lastname = document.getElementById("alert_lastname");
    const lastname = document.getElementById("lastname");
    lastname.addEventListener("change", function(ev){
        let message = "Last name can contain only letters";
        checkValide(lastname, 1, alert_lastname, message, valideName);
    });
   
    
    const alert_username = document.getElementById("alert_username");
    const username = document.getElementById("login");
    username.addEventListener("change", function(ev){
        let message = "Username already taken";
        checkValide(username, 2, alert_username, message, valideUsername);
    });
    
    everythingAlright[3] = true;
    /*const alert_gender = document.getElementById("alert_gender");
    const gender = document.getElementById("gender");
    gender.addEventListener("change", function(ev){
        let message = "Gender not chosen";
        checkValide(gender, 3, alert_gender, message, valideGender);
    });*/
    
    const alert_pass = document.getElementById("alert_pass");
    const pass1 = document.getElementById("password");
    pass1.addEventListener("change", function(ev){
        originValue = pass1.value;
       let message = "Short password";
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
