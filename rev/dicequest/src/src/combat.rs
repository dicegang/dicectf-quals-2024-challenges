use crate::money::ShopItem;
use crate::{
    Cooldown, Damage, Death, Enemy, GameState, Health, JustDied, OwnedItems, Player,
    DICE_ENEMY_SIZE, PLAYER_SIZE,
};
use bevy::prelude::*;
use bevy::sprite::collide_aabb::collide;
use bevy::sprite::Anchor;
use std::f32::consts::PI;

#[derive(Component)]
pub struct AttackCooldown(Timer);

#[derive(Bundle)]
struct SwingingSwordBundle {
    sprite: SpriteBundle,
    swing_timer: SwingTimer,
}

#[derive(Component)]
struct SwingTimer(Timer);

#[derive(Event)]
struct Attack {
    source: Entity,
    target: Entity,
    damage: f32,
}

pub struct CombatPlugin;

impl Plugin for CombatPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            Update,
            (
                (tick_attack_cooldowns, check_collisions, process_attacks)
                    .chain()
                    .run_if(in_state(GameState::Running)),
                animate_sword.run_if(in_state(GameState::Running)),
            ),
        )
        .add_event::<Attack>();
    }
}

const SWORD_BASE_ROTATION: f32 = PI / 2.0;

#[derive(Component, Default, Copy, Clone)]
enum NextSword {
    /// Pink, default sword
    #[default]
    One,
    /// Fire, upgraded sword
    Two,
}

impl NextSword {
    pub fn flip(&mut self) {
        *self = match self {
            NextSword::One => NextSword::Two,
            NextSword::Two => NextSword::One,
        }
    }

    pub fn sprite(&self) -> &'static str {
        match self {
            Self::One => "sord1.png",
            Self::Two => "sord2.png",
        }
    }
}

fn check_collisions(
    mut commands: Commands,
    mut player: Query<
        (
            Entity,
            &Transform,
            &Damage,
            &Cooldown,
            Option<&mut NextSword>,
            &OwnedItems,
        ),
        With<Player>,
    >,
    enemies: Query<(Entity, &Transform, &Damage, &Cooldown), With<Enemy>>,
    cooldowns: Query<&AttackCooldown>,
    assets: Res<AssetServer>,
    mut attacks: EventWriter<Attack>,
) {
    let (player, player_trans, player_damage, player_cooldown, mut next_sword, player_items) =
        player.single_mut();

    for (enemy, enemy_trans, enemy_damage, enemy_cooldown) in enemies.iter() {
        if collide(
            player_trans.translation,
            PLAYER_SIZE,
            enemy_trans.translation,
            DICE_ENEMY_SIZE,
        )
        .is_some()
        {
            if cooldowns.get_component::<AttackCooldown>(player).is_err() {
                attacks.send(Attack {
                    source: player,
                    target: enemy,
                    damage: player_damage.0,
                });
                let sword_to_use = if let Some(sword) = next_sword.as_deref_mut() {
                    // Alternate between our two sprites
                    let current = *sword;
                    sword.flip();
                    current
                } else if player_items.0.contains(&ShopItem::DualWield) {
                    // Our first swing after upgrading
                    commands.entity(player).insert(NextSword::One);
                    NextSword::Two
                } else {
                    // No upgrade, use standard
                    NextSword::One
                };
                commands
                    .entity(player)
                    .insert(AttackCooldown(Timer::from_seconds(
                        player_cooldown.0,
                        TimerMode::Once,
                    )))
                    .with_children(|player_commands| {
                        player_commands.spawn(SwingingSwordBundle {
                            sprite: SpriteBundle {
                                transform: Transform::from_translation(Vec3::new(50.0, 20.0, 1.0))
                                    .with_rotation(Quat::from_rotation_z(SWORD_BASE_ROTATION))
                                    .with_scale(Vec3::new(1.5, 1.5, 1.0)),
                                texture: assets.load(sword_to_use.sprite()),
                                sprite: Sprite {
                                    anchor: Anchor::TopLeft,
                                    ..default()
                                },
                                ..default()
                            },
                            swing_timer: SwingTimer(Timer::from_seconds(
                                player_cooldown.0,
                                TimerMode::Once,
                            )),
                        });
                    });
            }
            if cooldowns.get_component::<AttackCooldown>(enemy).is_err() {
                attacks.send(Attack {
                    source: enemy,
                    target: player,
                    damage: enemy_damage.0,
                });
                commands
                    .entity(enemy)
                    .insert(AttackCooldown(Timer::from_seconds(
                        enemy_cooldown.0,
                        TimerMode::Once,
                    )));
            }
        }
    }
}

fn animate_sword(
    time: Res<Time>,
    mut commands: Commands,
    mut sword: Query<(Entity, &mut Transform, &mut SwingTimer)>,
) {
    for (entity, mut transform, mut timer) in sword.iter_mut() {
        if timer.0.finished() {
            commands.entity(entity).despawn();
            return;
        }
        timer.0.tick(time.delta());
        *transform = transform.with_rotation(Quat::from_rotation_z(
            SWORD_BASE_ROTATION - (PI * timer.0.percent() / 2.0),
        ));
    }
}

fn tick_attack_cooldowns(
    mut commands: Commands,
    mut attacks: Query<(Entity, &mut AttackCooldown)>,
    time: Res<Time>,
) {
    for (entity, mut cooldown) in attacks.iter_mut() {
        cooldown.0.tick(time.delta());
        if cooldown.0.finished() {
            commands.entity(entity).remove::<AttackCooldown>();
        }
    }
}

fn process_attacks(
    mut commands: Commands,
    mut events: EventReader<Attack>,
    mut query: Query<(&mut Health, Has<Player>)>,
    mut next_state: ResMut<NextState<GameState>>,
    mut deaths: EventWriter<Death>,
) {
    for event in events.read() {
        let Ok((mut target, is_player)) = query.get_mut(event.target) else {
            continue;
        };
        let new_health = target.current - event.damage;
        target.current = new_health;
        if new_health <= 0.0 {
            deaths.send(Death {
                source: Some(event.source),
                target: event.target,
            });
            if is_player {
                // end the game
                println!("player died :(");
                next_state.set(GameState::GameOver);
            }
            commands.entity(event.target).insert(JustDied::new());
        }
    }
}
