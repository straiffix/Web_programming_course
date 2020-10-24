function attach_events(){

    var everythingAlright = new Array(6).fill(true);
    var submit = document.getElementById("submit");
    

    var alert_name = document.getElementById("alert_name");
    
    var firstname = document.getElementById("textname");
    firstname.addEventListener("change", function(ev){
        if(/\d/.test(firstname.value)){
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
            if(everythingAlright.every(function(check){return check===true})){
                submit.removeAttribute("disabled");
            }
        }
    });
    
    var alert_lastname = document.getElementById("alert_lastname");
    var lastname = document.getElementById("textlastname");
    lastname.addEventListener("change", function(ev){
        if(/\d/.test(lastname.value)){
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
    
    
    var alert_username = document.getElementById("alert_username");
    var username = document.getElementById("textusername");
    username.addEventListener("change", function(ev){
        let value = username.value;
        var xhr = new XMLHttpRequest();
        var request = 'https://infinite-hamlet-29399.herokuapp.com/check/' + value;
        xhr.onreadystatechange = function(){
            let DONE = 4;
            let OK = 200;
            if (xhr.readyState == DONE){
                if(xhr.status == OK){
                    console.log(xhr.responseText);
                } else {
                    alert_username.style.display = "none";
                    username.className = "alright";
                    
                }
            }
        };
        console.log(request);
        xhr.open('GET', request, true);
        xhr.send(null);
        
    });
    
    
    var alert_avatar = document.getElementById("alert_avatar");
    var avatar = document.getElementById("avatar");
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
