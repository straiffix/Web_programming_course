var common_keys;
var response_c;
function check_notifications(){
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function (){
        if (xhr.readyState == 4){
            response = JSON.parse(xhr.responseText);
            response_c = response;
            keys = Object.keys(response);
            common_keys = keys;
            for (var i=0; i< keys.length; i++){

                id = i;
                if (document.getElementById(id) == null){
                    message = response[id];
                    section = document.getElementById('for_mess');
                    
                    new_message = document.createElement('div');
                    new_message.innerHTML = message;
                    new_message.setAttribute('id', id)
                    new_message.setAttribute('class', 'alert alert-dismissible alert-info')
                                 
                    deleteButton = document.createElement('button');
                    deleteButton.innerHTML = 'close';
                    deleteButton.setAttribute('class', 'btn btn-primary'); 
                    deleteButton.setAttribute('id', 'button_' + id)
                    deleteButton.onclick = function(){
                        var xhr = new XMLHttpRequest();
                        xhr.open("POST", 'https://krukm-web-app.herokuapp.com/notif_get', true);
                        xhr.setRequestHeader('Content-Type', 'application/json');
                        del_id = this.getAttribute('id');
                        del_id = parseInt(del_id.split('_')[1]);
                        console.log(del_id);
                        xhr.send(JSON.stringify({
                           value: del_id
                        }));
                        section.innerHTML = '';
                    };             
                        
                    new_message.appendChild(deleteButton);               
                    section.appendChild(new_message);
                }
                
            }
            //console.info(xhr.responseText);
            setTimeout(check_notifications, 1000);
        }
    };
    
    
    //xhr.open("GET", 'http://0.0.0.0:5000/notif_get', true);
    xhr.open("GET", 'https://krukm-web-app.herokuapp.com/notif_get', true);
    xhr.timeout = 15000;
    xhr.ontimeout = function () {console.error("Timeout");
                                setTimeout(check_notifications, 1000) };
    xhr.send();
}
check_notifications();