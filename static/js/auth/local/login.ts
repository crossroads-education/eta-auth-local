$(document).ready(function() {
    $("#input-username").focus();
    $(".btn-register").on("click", function(evt: JQuery.Event) {
        evt.preventDefault();
        location.replace("/auth/local/register");
    });
});
