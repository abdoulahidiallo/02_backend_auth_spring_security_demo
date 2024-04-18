package com._Backend_auth.PkgAuth.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Constraint(validatedBy = StrongPasswordValidator.class)
@Target({ ElementType.METHOD, ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface StrongPassword {
    String message() default "Doit faire au moins 8 caractères et être composé d'une combinaison de lettres majuscules, de lettres minuscules, de chiffres et de caractères spéciaux.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}