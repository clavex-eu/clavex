import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider, QueryCache } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import toast from 'react-hot-toast'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  // Surface query (data-load) failures globally. Without this a failed list
  // fetch falls back to an empty array and renders as "No items yet", which
  // is indistinguishable from a genuinely empty result. The 401 case is
  // already handled by the axios interceptor (redirect to /login).
  queryCache: new QueryCache({
    onError: (error) => {
      const status = (error as { response?: { status?: number } })?.response?.status
      if (status === 401) return
      toast.error('Failed to load data. Please retry.')
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={queryClient}>
    <App />
    {import.meta.env.DEV && <ReactQueryDevtools initialIsOpen={false} />}
  </QueryClientProvider>,
)
