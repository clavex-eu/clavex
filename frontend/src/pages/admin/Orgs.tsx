import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import api, { toArr } from '@/lib/api'

interface Organization {
  id: string
  name: string
  slug: string
  is_active: boolean
  created_at: string
}

export default function OrgsPage() {
  const { data, isLoading, error } = useQuery<Organization[]>({
    queryKey: ['orgs'],
    queryFn: () => api.get('/organizations').then((r) => toArr(r.data)),
  })

  if (isLoading) return <p className="text-gray-500">Loading…</p>
  if (error) return <p className="text-red-600">Failed to load organizations.</p>

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-gray-900">Spaces</h1>
        <button className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700">
          New organization
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-200 overflow-hidden">
        {(data ?? []).length === 0 && (
          <p className="px-6 py-8 text-sm text-gray-500 text-center">
            No organizations yet.
          </p>
        )}
        {(data ?? []).map((org) => (
          <div key={org.id} className="flex items-center justify-between px-6 py-4">
            <div>
              <p className="font-medium text-gray-900">{org.name}</p>
              <p className="text-xs text-gray-400">{org.slug}</p>
            </div>
            <div className="flex items-center gap-4">
              <span
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                  org.is_active
                    ? 'bg-green-50 text-green-700'
                    : 'bg-gray-100 text-gray-500'
                }`}
              >
                {org.is_active ? 'Active' : 'Inactive'}
              </span>
              <Link
                to={`/organizations/${org.id}/users`}
                className="text-sm text-indigo-600 hover:underline"
              >
                Users
              </Link>
              <Link
                to={`/organizations/${org.id}/clients`}
                className="text-sm text-indigo-600 hover:underline"
              >
                Clients
              </Link>
              <Link
                to={`/organizations/${org.id}/audit`}
                className="text-sm text-indigo-600 hover:underline"
              >
                Audit
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
