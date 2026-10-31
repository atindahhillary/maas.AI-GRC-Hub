import world from '@svg-maps/world'
import { COUNTRY_OPTIONS } from '@/lib/policy'

const EU = ['at', 'be', 'bg', 'hr', 'cy', 'cz', 'dk', 'ee', 'fi', 'fr', 'de', 'gr', 'hu', 'ie', 'it', 'lv', 'lt', 'lu', 'mt', 'nl', 'pl', 'pt', 'ro', 'sk', 'si', 'es', 'se']

// Static server-rendered map: the real footprint of an org, never simulated attack traffic.
export function WorldMap({ countries }: { countries: string[] }) {
  const names: Record<string, string> = Object.fromEntries(COUNTRY_OPTIONS)
  const on = new Set(countries.flatMap((c) => (c === 'EU' ? EU : [c.toLowerCase()])))
  return (
    <svg viewBox={world.viewBox} className="w-full" role="img" aria-label={`Operating countries: ${countries.map((c) => names[c] ?? c).join(', ') || 'none set'}`}>
      {world.locations.map((l: { id: string; name: string; path: string }) => (
        <path key={l.id} d={l.path} fill={on.has(l.id) ? '#3987e5' : '#1b2a40'} stroke="#0e1726" strokeWidth="0.5">
          <title>{l.name}</title>
        </path>
      ))}
    </svg>
  )
}
