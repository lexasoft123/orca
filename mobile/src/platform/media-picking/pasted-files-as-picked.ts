import {
  MOBILE_STREAMED_FILE_MAX_BYTES,
  MobileFileTooLargeError,
  type PickedMobileFile
} from './media-picker-contract'
import { blobBase64Chunks } from './picked-file-base64-chunks'

/** Files pasted into a field, shaped like picked ones so they stream through the same upload. */
export async function* pastedFilesAsPicked(
  files: readonly File[]
): AsyncGenerator<PickedMobileFile> {
  for (const file of files) {
    const name = file.name.trim() || 'pasted-file'
    if (file.size > MOBILE_STREAMED_FILE_MAX_BYTES) {
      throw new MobileFileTooLargeError(name, MOBILE_STREAMED_FILE_MAX_BYTES)
    }
    yield {
      name,
      mime: file.type || 'application/octet-stream',
      byteLength: file.size,
      chunks: () => blobBase64Chunks(file)
    }
  }
}

/** Binds a stream uploader to pasted files. */
export const streamPastedFiles =
  (attach: (files: AsyncIterable<PickedMobileFile>) => Promise<void>) =>
  (files: readonly File[]): Promise<void> =>
    attach(pastedFilesAsPicked(files))
