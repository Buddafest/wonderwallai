/**
 * Jerry The Customer Service Bot Widget — Entry Point
 *
 * This file creates a shadow DOM container and mounts the React chat widget.
 * Store owners embed this with:
 *
 *   <script src="https://your-domain.com/static/sunsetbot-widget.iife.js"
 *           data-shop="my-store.myshopify.com"
 *           data-server="https://your-domain.com"
 *           data-color="#FF6B35">
 *   </script>
 */

import React from 'react'
import { createRoot } from 'react-dom/client'
import { Widget } from './Widget'

// Find the script tag to read data attributes
const scriptTag = document.currentScript as HTMLScriptElement | null
const shop = scriptTag?.getAttribute('data-shop') || ''
const server = scriptTag?.getAttribute('data-server') || window.location.origin
const color = scriptTag?.getAttribute('data-color') || '#FF6B35'
const position = scriptTag?.getAttribute('data-position') || 'bottom-right'
const ttsDefault = scriptTag?.getAttribute('data-tts') === 'on'

// Create container with shadow DOM for CSS isolation
const container = document.createElement('div')
container.id = 'sunsetbot-widget-root'
container.style.cssText = 'position:fixed;z-index:2147483647;'
document.body.appendChild(container)

// Shadow DOM prevents store CSS from interfering with widget styles
const shadow = container.attachShadow({ mode: 'open' })
const mountPoint = document.createElement('div')
shadow.appendChild(mountPoint)

// Mount React app inside shadow DOM
const root = createRoot(mountPoint)
root.render(
  <React.StrictMode>
    <Widget
      shop={shop}
      server={server}
      primaryColor={color}
      position={position as 'bottom-right' | 'bottom-left'}
      ttsDefault={ttsDefault}
    />
  </React.StrictMode>
)
