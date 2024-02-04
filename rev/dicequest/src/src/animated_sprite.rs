use bevy::prelude::*;

pub struct AnimatedSpritePlugin;
impl Plugin for AnimatedSpritePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, animate_sprites);
    }
}

#[derive(Bundle)]
pub struct AnimatedSpriteBundle {
    sheet: SpriteSheetBundle,
    indices: AnimationIndices,
    timer: AnimationTimer,
}

impl AnimatedSpriteBundle {
    pub fn new(
        handle: Handle<Image>,
        size: Vec2,
        columns: usize,
        rows: usize,
        texture_atlases: &mut Assets<TextureAtlas>,
    ) -> Self {
        let atlas = TextureAtlas::from_grid(handle, size, columns, rows, None, None);
        let handle = texture_atlases.add(atlas);
        Self {
            sheet: SpriteSheetBundle {
                texture_atlas: handle,
                sprite: TextureAtlasSprite::new(0),
                ..default()
            },
            indices: AnimationIndices((columns * rows) - 1),
            timer: AnimationTimer(Timer::from_seconds(0.2, TimerMode::Repeating)),
        }
    }

    pub fn with_transform(mut self, transform: Transform) -> Self {
        self.sheet.transform = transform;
        self
    }
}

#[derive(Component)]
struct AnimationIndices(usize);

#[derive(Component, Deref, DerefMut)]
struct AnimationTimer(Timer);

fn animate_sprites(
    time: Res<Time>,
    mut query: Query<(
        &AnimationIndices,
        &mut AnimationTimer,
        &mut TextureAtlasSprite,
    )>,
) {
    for (indices, mut timer, mut sprite) in query.iter_mut() {
        timer.tick(time.delta());
        if timer.just_finished() {
            sprite.index = if sprite.index == indices.0 {
                0
            } else {
                sprite.index + 1
            };
        }
    }
}
