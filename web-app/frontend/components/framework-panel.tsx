'use client';

import { FrameworkStatusResponse, SessionDetailsResponse, ServiceHealth } from './types';

type Props = {
  frameworkStatus: FrameworkStatusResponse | null;
  sessionDetails?: SessionDetailsResponse | null;
  compact?: boolean;
};

const serviceLabels = {
  p1: 'P1 Signer',
  p2: 'P2 E-JWKS',
  p3: 'P3 Guard',
  p4: 'P4 Revocation'
} as const;

function shortValue(value: string | number | null | undefined) {
  if (value === null || value === undefined || value === '') {
    return 'n/a';
  }

  const text = String(value);
  if (text.length <= 18) {
    return text;
  }

  return `${text.slice(0, 8)}...${text.slice(-8)}`;
}

function ServiceCard({ label, service }: { label: string; service: ServiceHealth }) {
  return (
    <article className="framework-service-card">
      <div className="framework-service-head">
        <strong>{label}</strong>
        <span className={service.healthy ? 'service-pill ok' : 'service-pill warn'}>
          {service.healthy ? 'Online' : 'Offline'}
        </span>
      </div>
      <p>{service.url}</p>
      <span className="service-detail">{service.error || 'Health check passed'}</span>
    </article>
  );
}

export function FrameworkPanel({ frameworkStatus, sessionDetails = null, compact = false }: Props) {
  if (!frameworkStatus && !sessionDetails) {
    return null;
  }

  const keyProof = sessionDetails?.p2.key_proof;
  const tokenMeta = sessionDetails?.p4.token_meta;
  const token = sessionDetails?.token;

  return (
    <section className={compact ? 'framework-panel compact' : 'framework-panel'}>
      <div className="framework-panel-head">
        <div>
          <span className="badge-label">Quitty Integration</span>
          <h2>{compact ? 'Framework Readiness' : 'Live Framework Pipeline'}</h2>
        </div>
        <p>
          {compact
            ? 'The web app is checking all external Quitty services before users enter the protected flow.'
            : 'This session is issued by P1, discoverable through P2, validated by P3, and revocable in P4.'}
        </p>
      </div>

      {frameworkStatus ? (
        <div className="framework-service-grid">
          <ServiceCard label={serviceLabels.p1} service={frameworkStatus.services.p1} />
          <ServiceCard label={serviceLabels.p2} service={frameworkStatus.services.p2} />
          <ServiceCard label={serviceLabels.p3} service={frameworkStatus.services.p3} />
          <ServiceCard label={serviceLabels.p4} service={frameworkStatus.services.p4} />
        </div>
      ) : null}

      {!compact && sessionDetails ? (
        <div className="framework-detail-grid">
          <article className="framework-detail-card">
            <div className="detail-card-head">
              <strong>Issued Token</strong>
              <span className="service-pill ok">Validated</span>
            </div>
            <div className="detail-kv"><span>Algorithm</span><b>{token?.alg || 'n/a'}</b></div>
            <div className="detail-kv"><span>KID</span><b>{shortValue(token?.kid)}</b></div>
            <div className="detail-kv"><span>JTI</span><b>{shortValue(token?.jti)}</b></div>
            <div className="detail-kv"><span>Issuer</span><b>{shortValue(token?.iss)}</b></div>
          </article>

          <article className="framework-detail-card">
            <div className="detail-card-head">
              <strong>P2 Merkle Evidence</strong>
              <span className="service-pill ok">Published</span>
            </div>
            <div className="detail-kv"><span>Proof KID</span><b>{shortValue(keyProof?.kid)}</b></div>
            <div className="detail-kv"><span>Proof Hops</span><b>{keyProof?.proof_hops ?? 'n/a'}</b></div>
            <div className="detail-kv"><span>Checkpoint</span><b>{keyProof?.checkpoint_idx ?? sessionDetails.p2.transparency_log?.checkpoint_idx ?? 'n/a'}</b></div>
            <div className="detail-kv"><span>Root Hash</span><b>{shortValue(keyProof?.root_hash || sessionDetails.p2.jwks_root?.root_hash)}</b></div>
          </article>

          <article className="framework-detail-card">
            <div className="detail-card-head">
              <strong>P4 Revocation State</strong>
              <span className={sessionDetails.p4.revoked ? 'service-pill warn' : 'service-pill ok'}>
                {sessionDetails.p4.revoked ? 'Revoked' : 'Active'}
              </span>
            </div>
            <div className="detail-kv"><span>Synced Token</span><b>{tokenMeta?.found ? 'Yes' : 'No'}</b></div>
            <div className="detail-kv"><span>Revocation Scope</span><b>{tokenMeta?.revocation_reason || 'none'}</b></div>
            <div className="detail-kv"><span>Synced At</span><b>{tokenMeta?.synced_at ? new Date(tokenMeta.synced_at).toLocaleString() : 'n/a'}</b></div>
            <div className="detail-kv"><span>Subject</span><b>{shortValue(tokenMeta?.sub || token?.sub)}</b></div>
          </article>
        </div>
      ) : null}
    </section>
  );
}
