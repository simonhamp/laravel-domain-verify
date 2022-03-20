<?php

namespace SunAsterisk\DomainVerifier\Strategies;

use Spatie\Dns\Dns;
use Spatie\Dns\Records\TXT;
use SunAsterisk\DomainVerifier\Contracts\Models\DomainVerifiable;
use SunAsterisk\DomainVerifier\DomainVerificationFacade;
use SunAsterisk\DomainVerifier\Results\VerifyResult;

class DNSRecord extends BaseStrategy
{
    /**
     * Verify domain ownership via TXT record
     *
     * @param string $url
     * @param DomainVerifiable $domainVerifiable
     * @return VerifyResult
     */
    public function verify(string $url, DomainVerifiable $domainVerifiable): VerifyResult
    {
        $record = DomainVerificationFacade::firstOrCreate($url, $domainVerifiable);

        if ($this->tokenExists($url, $record->token)) {
            $record->setVerified();
        } else {
            $record->setNotVerified();
        }

        return new VerifyResult($domainVerifiable, $url, $record);
    }

    protected function getTxtRecords($url)
    {
        $dns = new Dns();
        return $dns->getRecords($url, DNS_TXT);
    }

    protected function tokenExists($url, $token)
    {
        $verificationName = config('domain_verifier.verification_name');
        $verificationValue = "$verificationName=$token";

        return collect($this->getTxtRecords($url))
            ->reject(function (TXT $record) use ($verificationValue) {
                return $record->txt() !== $verificationValue;
            })
            ->isNotEmpty();
    }
}
