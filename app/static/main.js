window.addEventListener('DOMContentLoaded', event => {

    //Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }

});

window.onload = function() {

    //Tooltip initialize
    $(function () {
        $('[data-toggle="tooltip"]').tooltip();
      })
    $(function () {
        $('[data-bs-toggle="tooltip"]').tooltip();
      })

    //Show password toggler
    $('.password-toggler').on('click', function(e){
        var password_input = $(this).parent().find('input');
        if (password_input.attr('type') == 'password')
        {
            password_input.attr('type','text');
            $(this).find('i').removeClass('bi-eye-fill');
            $(this).find('i').addClass('bi-eye-slash-fill');
            $(this).attr('data-bs-original-title', 'Hide Password');
        }
        else 
        {
            password_input.attr('type', 'password');
            $(this).find('i').removeClass('bi-eye-slash-fill');
            $(this).find('i').addClass('bi-eye-fill');
            $(this).attr('data-bs-original-title', 'Show Password');
        }
        e.preventDefault();
    });
}