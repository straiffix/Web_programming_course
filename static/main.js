function attach_events(){

    const everythingAlright = new Array(6).fill(true);
    const submit = document.getElementById("submit");
    const regexLetters = /^[a-zA-Z]+$/;
    

    const alert_name = document.getElementById("alert_name");
    
    const firstname = document.getElementById("textname");
    firstname.addEventListener("change", function(ev){
        if(!regexLetters.test(firstname.value)){
        firstname.className = "error";
        alert_name.style.display = "block";
        alert_name.innerHTML = "Wrong name. Should contain only letters";
        everythingAlright[0] = false;
        submit.setAttribute("disabled", "");
        }
        else{
            firstname.className = "alright";
            alert_name.style.display = "none";
            everythingAlright[0] = true;
            if(everythingAlright.every((v) => v === true)){
                submit.removeAttribute("disabled");
            }
        }
    });
    
    const alert_lastname = document.getElementById("alert_lastname");
    const lastname = document.getElementById("textlastname");
    lastname.addEventListener("change", function(ev){
        if(!regexLetters.test(lastname.value)){
        lastname.className = "error";
        alert_lastname.style.display = "block";
        alert_lastname.innerHTML = "Wrong name. Should contain only letters";
        everythingAlright[1] = false;
        submit.setAttribute("disabled", "");
        }
        else{
            lastname.className = "alright";
            alert_lastname.style.display = "none";
            everythingAlright[1] = true;
            if(everythingAlright.every(function(check){return check===true})){
                    submit.removeAttribute("disabled");
                }
        }
    });
    
    
    const alert_username = document.getElementById("alert_username");
    const username = document.getElementById("textusername");
    username.addEventListener("change", function(ev){
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
                        alert_username.style.display = "none";
                        username.className = "alright";
                        everythingAlright[2] = true;
                        if(everythingAlright.every(function(check){return check===true})){
                    submit.removeAttribute("disabled");
                }
                    } else {
                        alert_username.style.display = "block";
                        username.className = "error";
                        alert_username.innerHTML = "Taken";
                        everythingAlright[2] = false;
                        submit.setAttribute("disabled", "");
                        
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
    
    const alert_pass2 = document.getElementById("alert_pass2");
    
    const pass1 = document.getElementById("textpass");
    const pass2 = document.getElementById("textpass_second");
    
    pass2.addEventListener("change", function(ev){
        let originValue = pass1.value;
        let newValue = pass2.value;
        if(!(newValue === originValue)){
            alert_pass2.style.display = "block";
            alert_pass2.innerHTML = 'Password does not match';
            pass2.className = 'error';
            everythingAlright[4] = false;
            submit.setAttribute("disabled", "");
        } else {
            alert_pass2.style.display = "none";
            alert_pass2.className = "alright";
            everythingAlright[4] = true;
            if(everythingAlright.every(function(check){return check===true})){
                    submit.removeAttribute("disabled");
                }
        
        }
    
    })
    
    
    
    const alert_avatar = document.getElementById("alert_avatar");
    const avatar = document.getElementById("avatar");
    avatar.addEventListener("change", function(ev){
        let value = avatar.value;
        let extension = value.split('.').pop();
        if (extension === "png" || extension == "jpg" ){
            alert_avatar.style.display = "none";
            avatar.className = "alright";
            everythingAlright[5] = true;
            if(everythingAlright.every(function(check){return check===true})){
                    submit.removeAttribute("disabled");
                }
        } else {
            alert_avatar.style.display = "block";
            alert_avatar.innerHTML = 'Wrong extension';
            avatar.className = "error";
            everythingAlright[5] = false;
            submit.setAttribute("disabled", "");
    
        }
    
    
    })
    
    
    
    

}


attach_events() 
