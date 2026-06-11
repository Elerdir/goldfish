//! Folders group entries. Folder names are plaintext metadata (shown in the
//! sidebar for navigation), never secret.

use uuid::Uuid;

use crate::DomainError;

/// Maximum length of a folder name, in Unicode scalar values.
pub const MAX_FOLDER_NAME: usize = 100;

/// Per-view visual overrides for the entry list.
///
/// Every field is optional or falsey by default, meaning "inherit the app
/// theme". A folder stores its [`Appearance`] in the vault; the "all entries"
/// view stores the same shape in frontend settings. The font *family* is
/// intentionally not customizable — it is shared app-wide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Appearance {
    /// Background color of the list panel (`#rgb`/`#rrggbb`/`#rrggbbaa`), or
    /// `None` to inherit.
    pub background: Option<String>,
    /// Entry text color, or `None` to inherit.
    pub text_color: Option<String>,
    /// Render entry text bold.
    pub bold: bool,
    /// Render entry text italic.
    pub italic: bool,
    /// Entry font size in px (clamped to [`Appearance::MIN_FONT`]..=
    /// [`Appearance::MAX_FONT`]), or `None` to inherit.
    pub font_size: Option<u16>,
}

impl Appearance {
    /// Smallest selectable font size, in px.
    pub const MIN_FONT: u16 = 10;
    /// Largest selectable font size, in px.
    pub const MAX_FONT: u16 = 28;

    /// Validates colors (must be `#` + 3/6/8 hex digits) and clamps the font
    /// size into range. Returns a normalized copy (colors lowercased).
    ///
    /// # Errors
    /// [`DomainError::InvalidField`] if a color is not a hex string.
    pub fn sanitized(self) -> Result<Self, DomainError> {
        Ok(Self {
            background: normalize_color(self.background, "background")?,
            text_color: normalize_color(self.text_color, "text color")?,
            bold: self.bold,
            italic: self.italic,
            font_size: self
                .font_size
                .map(|n| n.clamp(Self::MIN_FONT, Self::MAX_FONT)),
        })
    }
}

/// Accepts only `#` followed by 3, 6, or 8 hex digits, lowercasing the result.
/// Rejecting anything else keeps stored values safe to drop into inline CSS.
fn normalize_color(
    color: Option<String>,
    field: &'static str,
) -> Result<Option<String>, DomainError> {
    let Some(value) = color else {
        return Ok(None);
    };
    let hex = value.strip_prefix('#');
    let valid = hex
        .is_some_and(|h| matches!(h.len(), 3 | 6 | 8) && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if valid {
        Ok(Some(value.to_ascii_lowercase()))
    } else {
        Err(DomainError::InvalidField {
            field,
            reason: "must be a hex color like #1a2b3c",
        })
    }
}

/// A named container for entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Stable identifier (UUID v7).
    pub id: Uuid,
    /// Display name (trimmed, non-empty, ≤ [`MAX_FOLDER_NAME`] chars).
    pub name: String,
    /// Per-view visual overrides (default = inherit the app theme).
    pub appearance: Appearance,
}

impl Folder {
    /// Creates a folder with a fresh id and default appearance, validating the
    /// name.
    ///
    /// # Errors
    /// [`DomainError::EmptyField`] if blank; [`DomainError::FieldTooLong`] if the
    /// name exceeds [`MAX_FOLDER_NAME`].
    pub fn new(name: &str) -> Result<Self, DomainError> {
        Ok(Self {
            id: Uuid::now_v7(),
            name: Self::validate_name(name)?,
            appearance: Appearance::default(),
        })
    }

    /// Validates and normalizes a folder name (trim + length checks).
    ///
    /// # Errors
    /// As [`Folder::new`].
    pub fn validate_name(name: &str) -> Result<String, DomainError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(DomainError::EmptyField {
                field: "folder name",
            });
        }
        if name.chars().count() > MAX_FOLDER_NAME {
            return Err(DomainError::FieldTooLong {
                field: "folder name",
                max: MAX_FOLDER_NAME,
            });
        }
        Ok(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trims_and_accepts_valid_name() {
        let f = Folder::new("  Work  ").unwrap();
        assert_eq!(f.name, "Work");
    }

    #[test]
    fn new_rejects_blank() {
        assert!(matches!(
            Folder::new("   "),
            Err(DomainError::EmptyField {
                field: "folder name"
            })
        ));
    }

    #[test]
    fn new_rejects_too_long() {
        let long = "x".repeat(MAX_FOLDER_NAME + 1);
        assert!(matches!(
            Folder::new(&long),
            Err(DomainError::FieldTooLong {
                field: "folder name",
                ..
            })
        ));
    }

    #[test]
    fn new_folder_has_default_appearance() {
        assert_eq!(Folder::new("X").unwrap().appearance, Appearance::default());
    }

    #[test]
    fn appearance_accepts_hex_colors_and_clamps_font() {
        let a = Appearance {
            background: Some("#ABC".to_owned()),
            text_color: Some("#11223344".to_owned()),
            bold: true,
            italic: false,
            font_size: Some(999),
        }
        .sanitized()
        .unwrap();
        assert_eq!(a.background.as_deref(), Some("#abc")); // lowercased
        assert_eq!(a.text_color.as_deref(), Some("#11223344"));
        assert!(a.bold);
        assert_eq!(a.font_size, Some(Appearance::MAX_FONT));
    }

    #[test]
    fn appearance_rejects_non_hex_color() {
        let err = Appearance {
            background: Some("red; content: evil".to_owned()),
            ..Appearance::default()
        }
        .sanitized()
        .unwrap_err();
        assert!(matches!(
            err,
            DomainError::InvalidField {
                field: "background",
                ..
            }
        ));
    }

    #[test]
    fn appearance_none_stays_none() {
        let a = Appearance::default().sanitized().unwrap();
        assert_eq!(a, Appearance::default());
    }
}
