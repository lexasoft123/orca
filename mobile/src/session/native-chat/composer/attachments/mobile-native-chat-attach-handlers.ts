import type { MobileNativeChatImageAttachments } from './mobile-native-chat-image-attachments-contract'

/** The composer's + actions: Photos (gallery when the chat can take videos) and Files; none when the chat takes no attachments. */
export function mobileNativeChatAttachHandlers(
  accepts: boolean,
  images: Pick<MobileNativeChatImageAttachments, 'attachGallery' | 'attachImage' | 'attachFiles'>
): { onAttachImage?: () => void; onAttachFiles?: () => void } {
  if (!accepts) {
    return {}
  }
  const gallery = images.attachGallery ?? (() => images.attachImage('library'))
  return { onAttachImage: () => void gallery(), onAttachFiles: () => void images.attachFiles() }
}
