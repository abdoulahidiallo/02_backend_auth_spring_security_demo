package com._Backend_auth.PkgAuth.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        // Vérifier si la chaîne de caractères contient au moins :
        // - 1 chiffre
        // - 1 lettre minuscule
        // - 1 lettre majuscule
        // - 1 caractère spécial (@#$%^&+=!*())
        // - 8 caractères minimum
        return value.matches("^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!*()]).{8,}$");
    }
}
