function onFormSubmit(evt: JQuery.Event): boolean {
    if ($("#input-password").val() !== $("#input-confirmPassword").val()) {
        $("#error").text("The passwords you provided do not match.");
        $("#input-password,#input-confirmPassword").val("");
        evt.preventDefault();
        return false;
    }
    return true;
}

$(document).ready(function() {
    $("form").on("submit", onFormSubmit);
});
