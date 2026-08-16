// Spoof-intel feed client. A single GET returns the sending sources currently
// flagged as spoofing or bulk-abuse infrastructure, as IPv4 CIDRs. Any authorized
// source that overlaps one of these is stripped from the hardened SPF record.

export interface FlaggedSource {
  cidr: string;
  reason: string;
}

interface FeedResponse {
  sources?: FlaggedSource[];
}

export async function queryFeed(base: string): Promise<FlaggedSource[]> {
  const response = await fetch(`${base}/v1/flagged`);
  if (!response.ok) {
    throw new Error(`feed query failed: status ${response.status}`);
  }
  const data = (await response.json()) as FeedResponse;
  return data.sources ?? [];
}
