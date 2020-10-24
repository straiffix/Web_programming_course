function attach_events(){

    var everythingAlright = new Array(6).fill(true);

    var alert_name = document.getElementById("alert_name");
    
    var firstname = document.getElementById("textname");
    firstname.addEventListener("change", function(ev){
        if(/\d/.test(firstname.value)){
        firstname.style.backgroundColor = "red";
        alert_name.style.display = "block";
        alert_name.innerHTML = "Wrong name. Should contain only letters";
        everythingAlright[0] = false;
        }
        else{
        firstname.style.backgroundColor = "green";
        alert_name.style.display = "none";
        everythingAlright[0] = true;
        }
    });
    
    var alert_lastname = document.getElementById("alert_lastname");
    
    var lastname = document.getElementById("textlastname");
    lastname.addEventListener("change", function(ev){
        if(/\d/.test(lastname.value)){
        lastname.style.backgroundColor = "red";
        alert_lastname.style.display = "block";
        alert_lastname.innerHTML = "Wrong name. Should contain only letters";
        everythingAlright[1] = false;
        }
        else{
        lastname.style.backgroundColor = "green";
        alert_lastname.style.display = "none";
        everythingAlright[1] = true;
        }
    });
    
    var submit = document.getElementById("submit");
    submit.addEventListener("submit", function(ev){
        
    
    })

}

attach_events() 