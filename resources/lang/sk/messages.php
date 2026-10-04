<?php

declare(strict_types=1);

return [
    'errors' => [
        'invalid_credentials' => 'Tieto prihlasovacie údaje sa nezhodujú s našimi záznamami.',
        'invalid_token' => 'Tento odkaz je neplatný alebo jeho platnosť vypršala.',
        'invalid_code' => 'Tento kód je neplatný alebo jeho platnosť vypršala.',
        'challenge_invalid' => 'Platnosť tohto pokusu o prihlásenie vypršala. Prihláste sa znova.',
        'factor_failed' => 'Overenie zlyhalo. Skúste to znova.',
        'factor_not_allowed' => 'Tento spôsob overenia tu nie je možné použiť.',
        'invalid_invitation' => 'Táto pozvánka je neplatná alebo jej platnosť vypršala.',
        'refresh_invalid' => 'Platnosť vašej relácie vypršala. Prihláste sa znova.',
        'enrolment_required' => 'Pre tento účet je potrebné nastaviť ďalší spôsob overenia pri prihlásení, čo tu nie je možné.',
        'too_many_attempts' => 'Príliš veľa pokusov. Skúste to znova neskôr.',
        'account_disabled' => 'Tento účet bol deaktivovaný.',
        'account_locked' => 'Tento účet je dočasne zablokovaný.',
        'email_not_verified' => 'Najskôr overte svoju e-mailovú adresu.',
        'method_disabled' => 'Nenájdené.',
        'registration_closed' => 'Registrácia je uzavretá.',
        'invitation_required' => 'Na registráciu je potrebná pozvánka.',
        'reauthentication_required' => 'Ak chcete pokračovať, potvrďte svoju totožnosť.',
        'two_factor_required' => 'Dvojfaktorové overenie je povinné a nie je možné ho vypnúť.',
        'last_credential' => 'Toto je váš posledný spôsob prihlásenia a nie je možné ho odstrániť.',
        'two_factor_already_enabled' => 'Dvojfaktorové overenie je už zapnuté.',
        'two_factor_not_enabled' => 'Dvojfaktorové overenie nie je zapnuté.',
        'passkey_registration_failed' => 'Prístupový kľúč sa nepodarilo zaregistrovať.',
        'not_found' => 'Nenájdené.',
        'login_denied' => 'Toto prihlásenie bolo v záujme vašej bezpečnosti zablokované.',
        'password_check_unavailable' => 'Heslo sa momentálne nepodarilo skontrolovať. Skúste to znova.',
        'misconfigured' => 'Prihlasovanie momentálne nie je k dispozícii.',
    ],

    'two_factor' => [
        'qr_title' => 'Kód na nastavenie dvojfaktorového overenia',
    ],
];
