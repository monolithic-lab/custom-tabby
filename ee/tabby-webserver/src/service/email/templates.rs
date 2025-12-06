fn format_email(body: &'static str, replacements: &[(&str, &str)]) -> String {
    let mut body = body.to_string();
    for (name, replacement) in replacements {
        body = body.replace(name, replacement);
    }
    body
}

macro_rules! template_email {
    ($lit:ident: $($arg:ident),*) => {
        {
            let contents = include_str!(concat!(
                "../../../email_templates/",
                stringify!($lit),
                ".html"
            ));
            format_email(contents, &[
                $(
                    (&format!("{{{{{}}}}}", stringify!($arg).to_uppercase()), $arg)
                ),*
            ])
        }
    };
}

pub fn signup_success(external_url: &str, email: &str) -> String {
    template_email!(signup_success: external_url, email)
}
