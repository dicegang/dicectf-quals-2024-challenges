use crate::generated_coords::GEN_FLAG_COORDS;
use crate::money::ShopItem;
use crate::{
    Damage, Enemy, EnemyBundle, GameState, Health, OwnedItems, Player, ENEMY_ATTACK_COOLDOWN,
    ENEMY_HEALTH_MAX,
};
use bevy::asset::AssetServer;
use bevy::math::{Vec2, Vec3Swizzles};
use bevy::prelude::*;
use bevy_prng::ChaCha8Rng;
use bevy_rand::prelude::GlobalEntropy;
use rand_core::RngCore;

const DRAGON_SPEED: f32 = 200.0;
const DRAGON_TIME: f32 = 60.0;
// Health regenerated per second
const DRAGON_ENEMY_SIZE: Vec2 = Vec2::new(128., 128.);

pub struct DragonPlugin;

impl Plugin for DragonPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(DragonCountdown(Timer::from_seconds(
            DRAGON_TIME,
            TimerMode::Once,
        )))
        .add_state::<DragonState>()
        .add_systems(
            Update,
            (
                (move_dragons, spawn_dragon_enemies).run_if(in_state(DragonState::Spawning)),
                check_dragons.run_if(in_state(DragonState::Counting)),
            )
                .run_if(in_state(GameState::Running)),
        )
        .add_systems(OnEnter(DragonState::Counting), begin_dragons);
    }
}

#[derive(Resource)]
struct DragonCountdown(Timer);

#[derive(Component)]
struct RepeatingDragonSpawner {
    next_index: usize,
    timer: Timer,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default, States)]
enum DragonState {
    #[default]
    /// Counting down til the end of the game
    Counting,
    /// Spam spawning dragons
    Spawning,
}

#[derive(Component)]
struct Dragon(usize);

fn move_dragons(
    time: Res<Time>,
    player: Query<(&Transform, &OwnedItems), With<Player>>,
    mut dragons: Query<(&mut Transform, &mut Sprite, &Dragon), Without<Player>>,
) {
    let (player_pos, owned) = player.single();
    let player_pos = player_pos.translation.xy();
    let tamed = owned.0.contains(&ShopItem::TameDragon);
    for (mut trans, mut sprite, dragon_index) in dragons.iter_mut() {
        let (speed, target_pos) = if tamed {
            let (x, y) = GEN_FLAG_COORDS[dragon_index.0 % GEN_FLAG_COORDS.len()];
            (DRAGON_SPEED * 20.0, Vec2::new(x as f32, y as f32) * 128.0)
        } else {
            (DRAGON_SPEED, player_pos)
        };
        let pos = trans.translation.xy();
        let new_pos = pos + (target_pos - pos).normalize() * speed * time.delta_seconds();
        trans.translation = new_pos.extend(0.0);
        if new_pos.x >= target_pos.x {
            sprite.flip_x = false;
        } else {
            sprite.flip_x = true;
        }
    }
}

fn spawn_dragon_enemies(
    mut commands: Commands,
    mut spawn_dragon_timer: Query<&mut RepeatingDragonSpawner>,
    time: Res<Time>,
    asset_server: Res<AssetServer>,
    windows: Query<&Window>,
    mut rng: ResMut<GlobalEntropy<ChaCha8Rng>>,
    player: Query<(&Transform, &OwnedItems), With<Player>>,
) {
    let mut spawn_dragon_timer = spawn_dragon_timer.single_mut();
    spawn_dragon_timer.timer.tick(time.delta());
    if !spawn_dragon_timer.timer.just_finished() {
        return;
    }
    let (transform, items) = player.single();
    let color = Color::rgb(
        rng.next_u32() as f32 / u32::MAX as f32,
        rng.next_u32() as f32 / u32::MAX as f32,
        rng.next_u32() as f32 / u32::MAX as f32,
    );
    let transform = Transform::from_translation(crate::random_position_on_screen(
        rng,
        windows.single(),
        transform.translation,
    ));

    let mut dragon = commands.spawn((
        EnemyBundle {
            health: Health::new(ENEMY_HEALTH_MAX * 50.0),
            marker: Enemy,
            sprite: SpriteBundle {
                texture: asset_server.load("dagun.png"),
                transform,
                sprite: Sprite {
                    custom_size: Some(DRAGON_ENEMY_SIZE),
                    color,
                    ..default()
                },
                ..default()
            },
            damage: Damage(50.0),
            attack_cooldown: ENEMY_ATTACK_COOLDOWN,
            #[cfg(feature = "inspect")]
            _name: Name::new("Dragon"),
        },
        Dragon(spawn_dragon_timer.next_index),
    ));
    spawn_dragon_timer.next_index += 1;
    if items.0.contains(&ShopItem::TameDragon) {
        dragon.remove::<Enemy>();
    }
}

fn check_dragons(
    time: Res<Time>,
    mut countdown: ResMut<DragonCountdown>,
    mut dragon_state: ResMut<NextState<DragonState>>,
) {
    countdown.0.tick(time.delta());
    if countdown.0.just_finished() {
        dragon_state.set(DragonState::Spawning);
    }
}

fn begin_dragons(mut commands: Commands) {
    commands.spawn(RepeatingDragonSpawner {
        next_index: 0,
        timer: Timer::from_seconds(0.05, TimerMode::Repeating),
    });
}
